//		g++ -I/root/h/i -pthread -s -O3 -Os -Wfatal-errors -fpermissive  %.cpp -o %.hel  /root/h/l/libssh.a /usr/lib/x86_64-linux-gnu/libcrypto.so /usr/lib/x86_64-linux-gnu/libz.so 

#define LIBSSH_STATIC 1
#include <libssh/libssh.h>

#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#include "hnet.h"
#include "hthread.h"

#define MAXPENDING 200
#define BUF_SIZE 4096
#define PP(x) if(PRINT) cout << x <<endl;
int PRINT = 1, fs = sizeof(fd_set);
const char *username = "username";
const char *password = "";

const char *server_ip = "127.0.0.1";
int remote_listenport = 5555;

ssh_session sshlogin( char *host, char *user, char *pass, int port=22){
	ssh_session	session=ssh_new();
	int auth;
	ssh_options_set(session, SSH_OPTIONS_HOST, host);
	ssh_options_set(session, SSH_OPTIONS_USER, user);
	ssh_options_set(session, SSH_OPTIONS_PORT, &port);
	ssh_connect( session);
	auth = ssh_userauth_password(session,0, pass);
	if(auth==SSH_AUTH_SUCCESS) return session;
	return 0;
}
struct cla{
	ssh_channel channel;
	SOCK s;
};

// -> host
static void cl2(cla* a) {
	char *buf = new char[BUF_SIZE];
	int sent , n , m;
	SOCK s=a->s;
	ssh_channel channel=a->channel;
	while(1){
		sent = 0;
		n = ssh_channel_read(channel, buf, BUF_SIZE, 0);
		if(n < 1) break;
		
		while(sent < n) {
			PP( " cl2 " <<sent)
			m = send(s, buf+sent, n-sent, 0);
			if(m < 1) goto ret;
			sent += m;
		}
	}
	ret:
	delete[] buf;
	// a->s=0;
	Sleep(3000);
	cns(s)
	PP( " cl2 ok")
}	
tspool(cl2) *y;
// auto y = hspool(cl2, 9);

// -> client
static void copyloop(ssh_channel channel, SOCK s, char *buf) {
	struct cla a={channel, s};
	int n=0;
	y->put(&a);
	// while(a.s || n==BUF_SIZE ){
	while(1){
		n = recv(s, buf, BUF_SIZE, 0);
		PP( " cl " <<n)
		if(n<1) break;
		if(ssh_channel_write(channel, buf, n)!=n) break;
	}
	PP( " cl ok" )
}
lock l;
bool s2(ssh_channel channel, long ip, short port, char* buf, char *d1=0, char *d2=0, int len1=0, int len2=0 ){
	if(PRINT){
		l.ac();
		if (buf[0]<26)	cout << " channel  [socks"<< 0+buf[0];
		else			cout << " channel  ["<< buf[0]<<buf[1]<<buf[2]<<"   ";
		cout <<"]  connect to  "<< ip2str(ip) << "\t :  " << htons(port) << endl;
		l.re();
	}
	SOCK dest = connect_host(ip, port);
	if (dest==SOCK_E)
		return 0;
	if(d1)
		ssh_channel_write(channel , d1, len1);
    d2 && send(dest, d2, len2, 0);
	copyloop(channel, dest, buf);
	cns(dest)
	return 1;
}

bool s1(ssh_channel channel, char *buf) {
	long ip, len, i=0;
	len = ssh_channel_read(channel, buf, BUF_SIZE, 0);
	if(len<0)
		return 1;
	// PP("s1 "<<len)
	if(buf[0]==5){									//				SOCKS5
		buf[1]=0;
		if(ssh_channel_write(channel, buf, 2)!=2)
			return 1;
		len = ssh_channel_read(channel, buf, BUF_SIZE, 0);
		if(len<0)
			return 1;
		// PP("s1 2 "<<i);
		if(buf[3]-1 || buf[1]-1)
			return 0;
		return s2( channel, *(long*)(buf+4), *(short*)(buf+8), buf, "\x5\x0\x0\x1huongd",0, 10);
	}else if(buf[0]==4)								//				SOCKS4
		return s2( channel, *(long*)(buf+4), *(short*)(buf+2), buf, "\x0Zhuongd"        ,0, 8);
	else{
		char * c, *path ;
		buf[1986]=0;
		if(!(path = strchr(buf, 32))) return 0;
		path++;
		if(buf[0]==67){								//	 C			HTTPS
			if(!(c = strchr(path, 32))) return 0;
			*c = 0;
			if(!(c = strchr(buf, 58))) return 0;			//		 :
			*c++ = 0;
			return s2( channel, inet_addr(path), htons(atoi(c)), buf, "HTTP/1.1 200 Connection established\r\nProxy-agent: H\r\n\r\n", 0, 55);
		}else if(buf[1]>64 && buf[1]<86 ){			//				HTTP
			c = path+7;
			if(!(path = strchr(c, 47))) return 0;			//		 /
			*path = 0;
			if(!(ip = name2ip(c))) return 0;
			c = path - c + 7 + buf;
			memcpy(c, buf, path - c );
			*path = 47;
			return s2( channel, ip, 20480, buf, 0, c, 0, buf - c + len );
		}
	}
	return 0;
}
void handle_connection(ssh_channel channel) {
	char *buffer = new char[BUF_SIZE];
	s1(channel, buffer);
	delete[] buffer;
	ssh_channel_send_eof(channel);
    ssh_channel_free(channel);
}
// a.out 104.196.206.36 root h5fy4g6r 888
int main(int argc, char *argv[])
{
	ssh_session session;
	ssh_channel channel = 0;
	int n=26;
	if (argc > 1)
		server_ip = argv[1];
	if (argc > 2)
		username = argv[2];
	if (argc > 3)
		password = argv[3];
	if (argc > 4)
		remote_listenport = atoi(argv[4]);
	if (argc > 5)
		n = atoi(argv[5]);
	SOCKINIT
	if (ssh_init()) {
		return 1;
	}
	PP( "connecting");
	if (!(session = sshlogin(server_ip, username, password))) {
		return 1;
	}
	if(ssh_channel_listen_forward(session, 0, remote_listenport, 0)!=SSH_OK)
		return 1;
	auto x = hspool(handle_connection, n);
	y = hspool(cl2, n);
	PP( "listening ")
	while (1){
		if(channel = ssh_channel_accept_forward(session, 265000, 0))
			x->put(channel);
		PP( " channel "<< channel )
		hsleep
	}
shutdown:
	PP( "bye" )
	ssh_finalize();
	return 0;
}