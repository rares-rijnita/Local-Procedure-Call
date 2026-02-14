// SPDX-License-Identifier: BSD-3-Clause

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#include "protocol/components.h"

#define DISPATCHER_DIR ".dispatcher"
#define PIPES_DIR ".pipes"
#define INSTALL_REQ_PIPE ".dispatcher/install_req_pipe"
#define CONNECTION_REQ_PIPE ".dispatcher/connection_req_pipe"

static volatile sig_atomic_t g_running = 1;
static int g_client_counter = 0;

static void handle_sigint(int signum)
{
	(void)signum;
	g_running = 0;
}

static ssize_t read_exact(int fd, void *buf, size_t len)
{
	size_t off = 0;
	while (off < len) {
		ssize_t r = read(fd, (char *)buf + off, len - off);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (r == 0)
			return (ssize_t)off;
		off += (size_t)r;
	}
	return (ssize_t)off;
}

static ssize_t write_exact(int fd, const void *buf, size_t len)
{
	size_t off = 0;
	while (off < len) {
		ssize_t w = write(fd, (const char *)buf + off, len - off);
		if (w < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		off += (size_t)w;
	}
	return (ssize_t)off;
}

struct ServiceInfo {
	char *version;
	size_t version_len;
	char *call_pipe;
	size_t call_pipe_len;
	char *return_pipe;
	size_t return_pipe_len;
	char *access_path;
	size_t access_path_len;
	int available;
	int dummy_call_fd; // Keep pipe alive
	int dummy_return_fd; // Keep pipe alive
};

static struct ServiceInfo g_service = {0, 0, 0, 0, 0, 0, 0, 0, 0, -1, -1};
static pthread_mutex_t g_service_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_service_cv = PTHREAD_COND_INITIALIZER;

static int ensure_dir(const char *path)
{
	struct stat st;
	if (stat(path, &st) == 0) {
		if (S_ISDIR(st.st_mode))
			return 0;
		fprintf(stderr, "Path exists but is not a directory: %s\n", path);
		return -1;
	}
	if (mkdir(path, 0777) < 0 && errno != EEXIST) {
		perror("mkdir");
		return -1;
	}
	return 0;
}

static int ensure_fifo(const char *path, mode_t mode)
{
	struct stat st;
	if (stat(path, &st) == 0) {
		if (S_ISFIFO(st.st_mode))
			return 0;
		unlink(path);
	}
	if (mkfifo(path, mode) < 0 && errno != EEXIST) {
		perror("mkfifo");
		return -1;
	}
	return 0;
}

static int set_nonblocking(int fd)
{
	int flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0)
		return -1;
	return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static void free_service_info(struct ServiceInfo *svc)
{
	if (!svc)
		return;
	free(svc->version);
	free(svc->call_pipe);
	free(svc->return_pipe);
	free(svc->access_path);
	// Note: dummy fds are closed separately before calling free_service_info
	svc->version = NULL;
	svc->call_pipe = NULL;
	svc->return_pipe = NULL;
	svc->access_path = NULL;
	svc->available = 0;
}

static void *install_thread(void *arg)
{
	(void)arg;

	int req_fd = open(INSTALL_REQ_PIPE, O_RDONLY);
	if (req_fd < 0) {
		perror("open install_req_pipe");
		return NULL;
	}

	while (g_running) {
		struct InstallRequestHeader req_hdr;
		ssize_t r = read_exact(req_fd, &req_hdr, sizeof(req_hdr));
		if (r <= 0) {
			if (!g_running)
				break;
			close(req_fd);
			req_fd = open(INSTALL_REQ_PIPE, O_RDONLY);
			if (req_fd < 0) {
				perror("re-open install_req_pipe");
				break;
			}
			continue;
		}

		uint16_t ipn_len = be16toh(req_hdr.m_IpnLen);
		if (ipn_len == 0 || ipn_len > 65535)
			continue;

		char *install_pipe_name = (char *)malloc(ipn_len + 1);
		if (!install_pipe_name) {
			fprintf(stderr, "alloc fail install pipe name\n");
			break;
		}
		r = read_exact(req_fd, install_pipe_name, ipn_len);
		if (r != (ssize_t)ipn_len) {
			free(install_pipe_name);
			continue;
		}
		install_pipe_name[ipn_len] = '\0';

		ensure_fifo(install_pipe_name, 0666);
		int install_fd = open(install_pipe_name, O_RDONLY);
		if (install_fd < 0) {
			perror("open service install pipe");
			free(install_pipe_name);
			continue;
		}

		struct InstallHeader hdr;
		r = read_exact(install_fd, &hdr, sizeof(hdr));
		if (r != (ssize_t)sizeof(hdr)) {
			close(install_fd);
			free(install_pipe_name);
			continue;
		}

		uint8_t version_len = hdr.m_VersionLen;
		uint16_t cpn_len = be16toh(hdr.m_CpnLen);
		uint16_t rpn_len = be16toh(hdr.m_RpnLen);
		uint16_t ap_len = be16toh(hdr.m_ApLen);

		size_t total = (size_t)version_len + (size_t)cpn_len + (size_t)rpn_len + (size_t)ap_len;
		char *buf = (char *)malloc(total);
		if (!buf) {
			fprintf(stderr, "alloc fail install contents\n");
			close(install_fd);
			free(install_pipe_name);
			continue;
		}
		r = read_exact(install_fd, buf, total);
		close(install_fd);
		if (r != (ssize_t)total) {
			free(buf);
			free(install_pipe_name);
			continue;
		}

		char *p = buf;
		char *version = (char *)malloc(version_len + 1);
		char *call_pipe = (char *)malloc(cpn_len + 1);
		char *return_pipe = (char *)malloc(rpn_len + 1);
		char *access_path = (char *)malloc(ap_len + 1);
		if (!version || !call_pipe || !return_pipe || !access_path) {
			free(version);
			free(call_pipe);
			free(return_pipe);
			free(access_path);
			free(buf);
			free(install_pipe_name);
			continue;
		}
		memcpy(version, p, version_len);
		p += version_len;
		version[version_len] = '\0';
		memcpy(call_pipe, p, cpn_len);
		p += cpn_len;
		call_pipe[cpn_len] = '\0';
		memcpy(return_pipe, p, rpn_len);
		p += rpn_len;
		return_pipe[rpn_len] = '\0';
		memcpy(access_path, p, ap_len);
		access_path[ap_len] = '\0';

		ensure_fifo(call_pipe, 0666);
		ensure_fifo(return_pipe, 0666);
		
		// Open dummy fds to keep pipes alive (prevent SIGPIPE to service)
		int dummy_call = open(call_pipe, O_RDWR | O_NONBLOCK);
		int dummy_return = open(return_pipe, O_RDWR | O_NONBLOCK);

		pthread_mutex_lock(&g_service_mutex);
		// Close old dummy fds if any
		if (g_service.dummy_call_fd >= 0)
			close(g_service.dummy_call_fd);
		if (g_service.dummy_return_fd >= 0)
			close(g_service.dummy_return_fd);
		free_service_info(&g_service);
		g_service.version = version;
		g_service.version_len = version_len;
		g_service.call_pipe = call_pipe;
		g_service.call_pipe_len = cpn_len;
		g_service.return_pipe = return_pipe;
		g_service.return_pipe_len = rpn_len;
		g_service.access_path = access_path;
		g_service.access_path_len = ap_len;
		g_service.dummy_call_fd = dummy_call;
		g_service.dummy_return_fd = dummy_return;
		g_service.available = 1;
		pthread_cond_broadcast(&g_service_cv);
		pthread_mutex_unlock(&g_service_mutex);

		free(buf);
		free(install_pipe_name);
	}

	close(req_fd);
	return NULL;
}

static void handle_client_proxy(char *response_pipe, int client_id, char *service_version, size_t svc_vlen, char *service_call, char *service_return, char *client_call_pipe, char *client_return_pipe)
{
	// Child process - proxy between client and service
	ensure_fifo(client_call_pipe, 0666);
	ensure_fifo(client_return_pipe, 0666);
	ensure_fifo(response_pipe, 0666);

	uint8_t version_len = (uint8_t)svc_vlen;
	char *version = (char *)malloc(version_len + 1);
	if (version)
		memcpy(version, service_version, version_len);

	// Send connect response
	struct ConnectHeader chdr;
	chdr.m_VersionLen = version_len;
	chdr.m_CpnLen = htobe32(strlen(client_call_pipe));
	chdr.m_RpnLen = htobe32(strlen(client_return_pipe));

	// Create FIFO if it doesn't exist
	ensure_fifo(response_pipe, 0666);
	
	// Open with retries - client should open it soon
	int resp_fd = -1;
	for (int retry = 0; retry < 1000; retry++) {
		resp_fd = open(response_pipe, O_WRONLY | O_NONBLOCK);
		if (resp_fd >= 0)
			break;
		usleep(5000);  // 5ms
	}
	if (resp_fd >= 0) {
		struct iovec iov[4];
		iov[0].iov_base = &chdr;
		iov[0].iov_len = sizeof(chdr);
		iov[1].iov_base = version;
		iov[1].iov_len = version_len;
		iov[2].iov_base = client_call_pipe;
		iov[2].iov_len = strlen(client_call_pipe);
		iov[3].iov_base = client_return_pipe;
		iov[3].iov_len = strlen(client_return_pipe);
		writev(resp_fd, iov, 4);
		close(resp_fd);
	}
	free(version);

	// Proxy loop
	// Open pipes with O_RDWR to avoid blocking issues
	int ccall_fd = -1, cret_fd = -1, scall_fd = -1, sret_fd = -1;
	
	// Wait for client pipes with retries
	for (int retry = 0; retry < 500 && ccall_fd < 0; retry++) {
		ccall_fd = open(client_call_pipe, O_RDWR | O_NONBLOCK);
		if (ccall_fd < 0)
			usleep(10000);
	}
	for (int retry = 0; retry < 500 && cret_fd < 0; retry++) {
		cret_fd = open(client_return_pipe, O_RDWR | O_NONBLOCK);
		if (cret_fd < 0)
			usleep(10000);
	}
	
	// Service pipes should exist (service is already registered)
	scall_fd = open(service_call, O_RDWR | O_NONBLOCK);
	sret_fd = open(service_return, O_RDWR | O_NONBLOCK);

	if (ccall_fd < 0 || cret_fd < 0 || scall_fd < 0 || sret_fd < 0) {
		if (ccall_fd >= 0)
			close(ccall_fd);
		if (cret_fd >= 0)
			close(cret_fd);
		if (scall_fd >= 0)
			close(scall_fd);
		if (sret_fd >= 0)
			close(sret_fd);
		free(service_call);
		free(service_return);
		exit(1);
	}

	char buffer[8192];
	ssize_t n;

	// Read from client call pipe
	for (int retry = 0; retry < 200; retry++) {
		n = read(ccall_fd, buffer, sizeof(buffer));
		if (n > 0)
			break;
		if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
			break;
		usleep(5000);
	}

	if (n > 0) {
		// Acquire lock before accessing service pipes
		int lock_fd = open(".dispatcher/service.lock", O_CREAT | O_RDWR, 0666);
		if (lock_fd >= 0)
			flock(lock_fd, LOCK_EX);
		
		// Forward to service
		write_exact(scall_fd, buffer, n);

		// Wait for response
		for (int retry = 0; retry < 200; retry++) {
			n = read(sret_fd, buffer, sizeof(buffer));
			if (n > 0)
				break;
			if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
				break;
			usleep(5000);
		}

		// Release lock
		if (lock_fd >= 0) {
			flock(lock_fd, LOCK_UN);
			close(lock_fd);
		}

		if (n > 0)
			write_exact(cret_fd, buffer, n);
	}

	close(ccall_fd);
	close(cret_fd);
	close(scall_fd);
	close(sret_fd);
	// Note: don't free version - child will exit anyway
	_exit(0);
}

static void *connect_thread(void *arg)
{
	(void)arg;
	int req_fd = open(CONNECTION_REQ_PIPE, O_RDONLY);
	if (req_fd < 0) {
		perror("open connection_req_pipe");
		return NULL;
	}

	while (g_running) {
		struct ConnectionRequestHeader req_hdr;
		ssize_t r = read_exact(req_fd, &req_hdr, sizeof(req_hdr));
		if (r <= 0) {
			if (!g_running)
				break;
			close(req_fd);
			req_fd = open(CONNECTION_REQ_PIPE, O_RDONLY);
			if (req_fd < 0) {
				perror("re-open connection_req_pipe");
				break;
			}
			continue;
		}

		uint32_t rpn_len = be32toh(req_hdr.m_RpnLen);
		uint32_t ap_len = be32toh(req_hdr.m_ApLen);
		if (rpn_len == 0 || ap_len == 0)
			continue;

		char *response_pipe = (char *)malloc((size_t)rpn_len + 1);
		char *access_path = (char *)malloc((size_t)ap_len + 1);
		if (!response_pipe || !access_path) {
			free(response_pipe);
			free(access_path);
			continue;
		}
		r = read_exact(req_fd, response_pipe, rpn_len);
		if (r != (ssize_t)rpn_len) {
			free(response_pipe);
			free(access_path);
			continue;
		}
		r = read_exact(req_fd, access_path, ap_len);
		if (r != (ssize_t)ap_len) {
			free(response_pipe);
			free(access_path);
			continue;
		}
		response_pipe[rpn_len] = '\0';
		access_path[ap_len] = '\0';

		// Get service info before forking
		pthread_mutex_lock(&g_service_mutex);
		while (!g_service.available && g_running)
			pthread_cond_wait(&g_service_cv, &g_service_mutex);
		if (!g_running) {
			pthread_mutex_unlock(&g_service_mutex);
			free(response_pipe);
			free(access_path);
			continue;
		}
		
		char *service_version = strdup(g_service.version);
		size_t svc_vlen = g_service.version_len;
		char *service_call = strdup(g_service.call_pipe);
		char *service_return = strdup(g_service.return_pipe);
		pthread_mutex_unlock(&g_service_mutex);

		// Fork child process to handle this client
		int client_id = __sync_fetch_and_add(&g_client_counter, 1);
		
		// Create client pipes before fork to avoid timing issues
		char client_call_pipe[256];
		char client_return_pipe[256];
		snprintf(client_call_pipe, sizeof(client_call_pipe), ".pipes/client_%d_call", client_id);
		snprintf(client_return_pipe, sizeof(client_return_pipe), ".pipes/client_%d_return", client_id);
		ensure_fifo(client_call_pipe, 0666);
		ensure_fifo(client_return_pipe, 0666);
		
		pid_t pid = fork();
		if (pid < 0) {
			perror("fork");
			free(response_pipe);
			free(access_path);
			free(service_version);
			free(service_call);
			free(service_return);
			continue;
		}

		if (pid == 0) {
			// Child process
			close(req_fd);
			handle_client_proxy(response_pipe, client_id, service_version, svc_vlen, service_call, service_return, 
							   client_call_pipe, client_return_pipe);
			_exit(0);
		}

		// Parent process
		free(response_pipe);
		free(access_path);
		free(service_version);
		free(service_call);
		free(service_return);
	}

	close(req_fd);
	return NULL;
}

int main(void)
{
	signal(SIGINT, handle_sigint);
	signal(SIGTERM, handle_sigint);
	signal(SIGCHLD, SIG_IGN);
	signal(SIGPIPE, SIG_IGN);

	if (ensure_dir(DISPATCHER_DIR) < 0)
		return 1;
	if (ensure_dir(PIPES_DIR) < 0)
		return 1;

	if (ensure_fifo(INSTALL_REQ_PIPE, 0666) < 0)
		return 1;
	if (ensure_fifo(CONNECTION_REQ_PIPE, 0666) < 0)
		return 1;

	pthread_t th_install, th_connect;
	if (pthread_create(&th_install, NULL, install_thread, NULL) != 0) {
		perror("pthread_create install");
		return 1;
	}
	if (pthread_create(&th_connect, NULL, connect_thread, NULL) != 0) {
		perror("pthread_create connect");
		g_running = 0;
		pthread_join(th_install, NULL);
		return 1;
	}

	while (g_running)
		pause();

	pthread_cancel(th_install);
	pthread_cancel(th_connect);
	pthread_join(th_install, NULL);
	pthread_join(th_connect, NULL);

	pthread_mutex_lock(&g_service_mutex);
	if (g_service.dummy_call_fd >= 0)
		close(g_service.dummy_call_fd);
	if (g_service.dummy_return_fd >= 0)
		close(g_service.dummy_return_fd);
	free_service_info(&g_service);
	pthread_mutex_unlock(&g_service_mutex);

	while (waitpid(-1, NULL, WNOHANG) > 0)
		;

	return 0;
}
