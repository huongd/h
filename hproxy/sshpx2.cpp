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
lock l;
int ssend( ssh_channel c , char *buf, int n){
	l.ac();
	n = ssh_channel_write(c , buf, n);
	l.re();
	return n;
}
int srecv( ssh_channel c , char *buf, int n, int x=0){
	l.ac();
	n = ssh_channel_read(c , buf, n, 0);
	l.re();
	return n;
}
int nsrecv( ssh_channel c , char *buf, int n, int x=0){
	l.ac();
	n = ssh_channel_read_nonblocking(c , buf, n, 0);
	l.re();
	return n;
}

static void copyloop(ssh_channel channel, SOCK s, char *buf) {
	int n=0,i=0,sent , m;
	while(i++<555){
		if(sock_readable(s)){
			i=0;
			n = recv(s, buf, BUF_SIZE, 0);
			if(n<1) {i = 3000; break;}
			if(ssend(channel, buf, n)!=n) i=4000;
		}
		if((n = nsrecv(channel, buf, BUF_SIZE, 0))>0){
			i=0;
			if(send(s, buf, n, 0)!=n) i=6000;
		}
		hsleep
		l.ac();
		if(	ssh_channel_is_eof(channel))
			i=5000;
		l.re();
		
		// else if(n<0) i=700;
		// PP( " cl "<<i )
		
	}
	PP( " cl ok " <<i)
	// return;
	// ret:
	// PP( " cl ret " <<i)
	// return;
	// ret2:
	// PP( " cl ret2 " <<i)
	// return;
	// ret3:
	// PP( n<<" cl ret3 " <<i)
}

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
		ssend(channel , d1, len1);
    d2 && send(dest, d2, len2, 0);
	copyloop(channel, dest, buf);
	cns(dest)
	return 1;
}

bool s1(ssh_channel channel, char *buf) {
	long ip, len, i=0;
	len = srecv(channel, buf, BUF_SIZE, 0);
	if(len<0)
		return 1;
	// PP("s1 "<<len)
	if(buf[0]==5){									//				SOCKS5
		buf[1]=0;
		if(ssend(channel, buf, 2)!=2)
			return 1;
		len = srecv(channel, buf, BUF_SIZE, 0);
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
	l.ac();
	ssh_channel_send_eof(channel);
    ssh_channel_free(channel);
	l.re();
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
	PP( "listening ")
	int i=0;
	while (1){
		l.ac();
		if(channel = ssh_channel_accept_forward(session, 5, 0))
			x->put(channel);
		l.re();
		// PP( i++<<" channel "<< channel <<"  | "<< x-> jobq.size()+0 )
		hsleep
	}
shutdown:
	PP( "bye" )
	ssh_finalize();
	return 0;
}