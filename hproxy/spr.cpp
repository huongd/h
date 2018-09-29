//		g++ -I/root/h/i -pthread -s -O3 -Os -Wfatal-errors -fpermissive %.cpp   /root/h/l/libssh2l.a -lssl -lcrypto -o %.hel

// #include <linux_libssh2_config.h>
#include "linux_libssh2_config.h"
#include <libssh2.h>

#include <ctime>

#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#include "hnet.h"
#include "hthread.h"

#define BUF_SIZE 4096
#define PP(x) if(PRINT) cout << x <<endl;
int PRINT = 1, fs = sizeof(fd_set);
const char *username = "root";
const char *password = "";
const char *server_ip = "127.0.0.1";
const char *remote_listenhost = "0.0.0.0";
int remote_wantport = 2222;
int remote_listenport;
lock l;
#define srecv0 libssh2_channel_read
#define ssend0 libssh2_channel_write
int ssend(LIBSSH2_CHANNEL* channel, char* buf, int len){
	int wr=0,i;
	l.ac();
	while (wr < len) {
		sleep001
		i = ssend0(channel, buf+wr, len-wr);
		if (i < 1)	break;
		wr += i;
	}
	l.re();
	return wr;
}
int srecv(LIBSSH2_CHANNEL* channel, char* buf, int len){
	int r=0, i=0;
	l.ac();
	while(i++<265&&(r==0||r==LIBSSH2_ERROR_EAGAIN)){
		usleep(100);
		r = srecv0(channel, buf, len);
	}
	l.re();
	return r;
}
static void copyloop2(LIBSSH2_CHANNEL* channel, SOCK s, char *buf) {
	int n=0,i=0;
	while(i++<2605){
		if(sock_readable(s)){
			i=0;
			n = recv(s, buf, BUF_SIZE, 0);
			// PP( n<<" cl1 "<<i )
			if(n<1) {i = 3000; break;}
			if(ssend(channel, buf, n)!=n) i=4000;
		}
		if((n = srecv(channel, buf, BUF_SIZE))>0){
			// PP( n<<" cl "<<i )
			i=0;
			if(send(s, buf, n, 0)!=n) i=6000;
		}
		// else if(n!=LIBSSH2_ERROR_EAGAIN&&n<0){
			// i=7000;
			// break;
		// }
		// hsleep
		sleep001
		l.ac();
		if(	libssh2_channel_eof(channel))
			i=5000;
		l.re();
	}
	PP( " cl ok " <<i)
}
static void copyloop(LIBSSH2_CHANNEL *channel, SOCK forwardsock, char *buf) {
	fd_set fds;
	struct timeval tv={0,10000};
	ssize_t len, wr, i, rc, j, k;
	for (k=0;k++<265;) {
		l.ac();
		// int start_s=clock();

		for (j=0;j++<86;) {
			FD_ZERO(&fds);
			FD_SET(forwardsock, &fds);
			rc = select(forwardsock + 1, &fds, 0, 0, &tv);
			if (-1 == rc) 
				goto ret;
			if (rc && FD_ISSET(forwardsock, &fds)) {
				len = recv(forwardsock, buf, BUF_SIZE, 0);
				if (len < 1) 
					goto ret;
				k=0;
				wr = 0;
				while (wr < len) {
					i = ssend0(channel, buf+wr, len-wr);//
					if (i < 1)
						goto ret;
					wr += i;
				} 
			}
			while (1) {
				len = srecv0(channel, buf, BUF_SIZE);//
				if (LIBSSH2_ERROR_EAGAIN == len)
					break;
				else if (len < 0)
					goto ret;
				if(len){
					k=0;
					if(send(forwardsock, buf , len , 0)<1) 
						goto ret;
				}
				if (libssh2_channel_eof(channel))//
					goto ret;
				
			}
		}
		// cout << "time ms: " << (clock()-start_s)/float(CLOCKS_PER_SEC)*1000 << endl;
		l.re();
		sleep1
	}
	return;
	ret:
	PP( j<<" cl jk " <<k)
	l.re();
}

bool s2(LIBSSH2_CHANNEL* src, long ip, short port, char* buf, char *d1=0, char *d2=0, int len1=0, int len2=0 ){
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
		ssend(src , d1, len1);
    d2 && send(dest, d2, len2, 0);
	copyloop(src, dest, buf);
	cns(dest)
	return 1;
}

bool s1(LIBSSH2_CHANNEL* sock, char *buf) {
	long ip, len=0, i=0;
	len=srecv(sock, buf, BUF_SIZE);
	if(len<0)
		return 1;

	if(buf[0]==5){									//				SOCKS5
		buf[1]=0;
		ssend(sock, buf, 2);
		srecv(sock, buf, BUF_SIZE);
		if(buf[3]-1 || buf[1]-1)
			return 0;
		return s2( sock, *(long*)(buf+4), *(short*)(buf+8), buf, "\x5\x0\x0\x1huongd",0, 10);
	}else if(buf[0]==4)								//				SOCKS4
		return s2( sock, *(long*)(buf+4), *(short*)(buf+2), buf, "\x0Zhuongd"        ,0, 8);
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
			return s2( sock, inet_addr(path), htons(atoi(c)), buf, "HTTP/1.1 200 Connection established\r\nProxy-agent: H\r\n\r\n", 0, 55);
		}else if(buf[1]>64 && buf[1]<86 ){			//				HTTP
			c = path+7;
			if(!(path = strchr(c, 47))) return 0;			//		 /
			*path = 0;
			if(!(ip = name2ip(c))) return 0;
			c = path - c + 7 + buf;
			memcpy(c, buf, path - c );
			*path = 47;
			return s2( sock, ip, 20480, buf, 0, c, 0, buf - c + len );
		}
	}
	return 0;
}
void handle_connection(LIBSSH2_CHANNEL* channel) {
	char *buffer = new char[BUF_SIZE];
	s1(channel, buffer);
	delete[] buffer;
	l.ac();
	libssh2_channel_free(channel);
	l.re();
}
// a.out 104.196.206.36 root h5fy4g6r 888 
// ./spr.hel 127.0.0.1 root h5fy4g6r 888 
int main(int argc, char *argv[])
{
	LIBSSH2_SESSION *session;
	LIBSSH2_LISTENER *listener = 0;
	LIBSSH2_CHANNEL *channel = 0;
	int err;
	char i=0;
	SOCK sock = -1;
	DECRYPTH
	if (argc > 1)
		server_ip = argv[1];
	if (argc > 2)
		username = argv[2];
	if (argc > 3)
		password = argv[3];
	if (argc > 4)
		remote_wantport = atoi(argv[4]);
	if (argc > 6)
		remote_listenhost = argv[6];
	if (argc>5)
		PRINT= atoi (argv[5]);
	if (libssh2_init(1)) {
		return 1;
	}
	SOCKINIT
	PP( "connecting");
	if ((sock = connect_host(server_ip, 22)) == SOCK_E)
		return 1;
	if (!(session = libssh2_session_init())) {
		return 1;
	}
	if (libssh2_session_handshake(session, sock))
		goto shutdown;
	PP( "loging in")
	if (libssh2_userauth_password(session, username, password)) 	
		goto shutdown;
	PP( "creating listener")
	listener = libssh2_channel_forward_listen_ex(session, remote_listenhost,
		remote_wantport, &remote_listenport, 26);
	if (!listener)
		goto shutdown;
	libssh2_session_set_blocking(session, 0);
	auto x = hspool(handle_connection, 26);
	PP( "listening")
	while (1){
		i+=16;
		l.ac();
		if(channel = libssh2_channel_forward_accept(listener)){
			x->put(channel);
		}else if(!i&&(libssh2_session_last_errno(session)-LIBSSH2_ERROR_EAGAIN))
			goto shutdown;
		l.re();
		sleep05
	}
	libssh2_channel_forward_cancel(listener);
shutdown:
	PP( "bye" )
	libssh2_session_disconnect(session, "Client disconnecting normally");
	libssh2_session_free(session);
	cns(sock)
	libssh2_exit();
	return 0;
}