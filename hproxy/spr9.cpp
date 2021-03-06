//		g++ -I/root/h/i -pthread -s -O3 -Os -Wfatal-errors -fpermissive %.cpp   /root/h/l/libssh2l.a -lssl -lcrypto -o %.eol ; upx %.eol
//		g++.exe -Id:/h/i -pthread -s -O3 -Os -Wfatal-errors -fpermissive %.cpp   d:/h/l/libssh2.a -o %.exe   -lws2_32 -lbcrypt -lcrypt32 -lws2_32 -lkernel32 -luser32 -lgdi32 -lwinspool -lshell32 -lole32 -loleaut32 -luuid -lcomdlg32 -ladvapi32 ; upx.exe %.exe
//		lock macro
//		./%.eol 2ChRimVPi.xsfBHRyzsZLJhP8jwvfuaYIZhStsUKX3FJ
//		./%.eol 104.196.206.36 root h5fy4g6r 888 1 38
//		./%.eol 127.0.0.1 root h5fy4g6r 888 1 26 huongdoanminh@gmail.com
#include <libssh2.h>
#include <hnet.h>
#include <hthread.h>
#define BUF_SIZE 4096
#define PP(x) if(PRINT) cout << x <<endl;
#define s_revc libssh2_channel_read
#define s_send libssh2_channel_write
#define lb(x) L_ACQUIRE x; L_RELEASE
int PRINT = 1;
const char *username = "root";
const char *password = "";
const char *server_ip = "127.0.0.1";
const char *remote_listenhost = "0.0.0.0";
int remote_wantport = 5555;
int remote_listenport;

int ssend(LIBSSH2_CHANNEL* channel, char* buf, int len, int c= 86){
	int wr=0,i;
	while(c--){
		lb(i = s_send(channel, buf+wr, len-wr))
		if (i < 0&&i!=LIBSSH2_ERROR_EAGAIN || ( i>0&&(c= 86)&&( wr += i)>=len ) )	break;
		sleep1
	}
	return wr;
}
int srecv(LIBSSH2_CHANNEL* channel, char* buf, int c = 26){
	int r;
	while(c--){
		lb(	r = s_revc(channel, buf, BUF_SIZE) )
		if(r&&r!=LIBSSH2_ERROR_EAGAIN) break;
		sleep1
	}
	return r;
}
int copyloop(LIBSSH2_CHANNEL *channel, SOCK forwardsock, char *buf) {
	ssize_t len, k, eof;
	unsigned long rc;
	for (k=0;k++<86;) {
		if sock_rc(forwardsock) {
			len = recv(forwardsock, buf, BUF_SIZE, 0);
			if (len < 1) return 1;
			k=0;
			if(ssend(channel, buf, len)-len) return 2;
		}
		L_ACQUIRE
		len = s_revc(channel, buf, BUF_SIZE);//
		if (len < 0&&len!=LIBSSH2_ERROR_EAGAIN){
			L_RELEASE
			return 3;
		}
		eof = libssh2_channel_eof(channel);//
		L_RELEASE
		if(len>0){
			k=0;
			if(send(forwardsock, buf , len , 0)<1) 	return 4;
		}
		if(eof)	return 5;
		if(k) sleep1
		sleep001
	}
	return 0;
}
int s2(LIBSSH2_CHANNEL* src, long ip, short port, char* buf, char *d1=0, char *d2=0, int len1=0, int len2=0 ){
	if(PRINT){
		lb(	
			if (buf[0]<26)	cout << " channel  [socks"<< 0+buf[0];
			else			cout << " channel  ["<< buf[0]<<buf[1]<<buf[2]<<"   ";
			cout <<"]  connect to  "<< ip2str(ip) << "\t :  " << htons(port) << endl;
		)
	}
	SOCK dest = connect_host(ip, port);
	if (dest==SOCK_E)
		return 21;
	d1 && ssend(src , d1, len1);
    d2 && send(dest, d2, len2, 0);
	copyloop(src, dest, buf);
	cns(dest)
	return 0;
}
int s1(LIBSSH2_CHANNEL* sock) {
	char buf[BUF_SIZE];
	long ip, len = srecv(sock, buf);
	if(len<2||len==BUF_SIZE)							return 1;
	if(buf[0]==5){									//				SOCKS5
		buf[1]=0;
		ssend(sock, buf, 2);
		if(srecv(sock, buf)<9 || buf[3]-1 || buf[1]-1)			return 2;
		return s2( sock, *(long*)(buf+4), *(short*)(buf+8), buf, "\x5\x0\x0\x1huongd",0, 10);
	}else if(buf[0]==4)								//				SOCKS4
		return s2( sock, *(long*)(buf+4), *(short*)(buf+2), buf, "\x0Zhuongd"        ,0, 8);
	else{
		char * c, *path ;
		buf[len]=0;
		if(!(path = strchr(buf, 32))) return 3;
		path++;
		if(buf[0]==67){								//	 C			HTTPS
			if(!(c = strchr(path, 32))) return 4;
			*c = 0;
			if(!(c = strchr(buf, 58))) return 5;			//		 :
			*c++ = 0;
			return s2( sock, inet_addr(path), htons(atoi(c)), buf, "HTTP/1.1 200 Connection established\r\nProxy-agent: H\r\n\r\n", 0, 55);
		}else if(buf[1]>64 && buf[1]<86 ){			//				HTTP
			c = path+7;
			if(!(path = strchr(c, 47))) return 6;			//		 /
			*path = 0;
			if(!(ip = name2ip(c))) return 7;
			c = path - c + 7 + buf;
			memcpy(c, buf, path - c );
			*path = 47;
			return s2( sock, ip, 20480, buf, 0, c, 0, buf - c + len );
		}
	}
	return 8;
}
void handle_connection(LIBSSH2_CHANNEL* channel) {
	s1(channel);
	lb(	libssh2_channel_send_eof(channel);	libssh2_channel_free(channel) )
}
LIBSSH2_SESSION* sshlogin( char *host, char *user, char *pass, int port=22){
	PP( "connecting");
	SOCK sock;
	LIBSSH2_SESSION *session;
	if ((sock = connect_host(host, port)) == SOCK_E)		return 0;
	if (!(session = libssh2_session_init())) 				return 0;
	if (libssh2_session_handshake(session, sock))			return 0;
	PP( "loging in")
	if (libssh2_userauth_password(session, user, pass)) 	return 0;
	return session;
}

int main(int argc, char *argv[])
{
	LIBSSH2_SESSION *session;
	LIBSSH2_LISTENER *listener = 0;
	LIBSSH2_CHANNEL *channel = 0;
	int nth=26;
	DECRYPTH
	if (argc > 1)		server_ip = argv[1];
	if (argc > 2)		username = argv[2];
	if (argc > 3)		password = argv[3];
	if (argc > 4)		remote_wantport = atoi(argv[4]);
	if (argc > 7)		remote_listenhost = argv[7];
	if (argc > 6)		nth = atoi(argv[6]);
	if (argc > 5)		PRINT= atoi (argv[5]);
	if (libssh2_init(0)) 		return 1;
	SOCKINIT
	PP( "\t\t ssh proxy reverse \n\t Copyright huongdoanminh@gmail.com \n\n\n" )
	PP( "\t\t "<< nth<<" -> "<<265 << " threads in dynamic mode \n\n" )
	auto x = hpool(handle_connection, nth, 265);
	int ec = 0, ec2 = 0;
retry:
	if(!(session = sshlogin(server_ip, username, password )))
		goto shutdown;
	PP( "creating listener")
	listener = libssh2_channel_forward_listen_ex(session, remote_listenhost, remote_wantport, &remote_listenport, 86);
	if (!listener)
		goto shutdown;
	libssh2_keepalive_config(session, 1, 26);
	libssh2_session_set_blocking(session, 0);
	ec = 0;
	if(!remote_wantport)
		PP(remote_listenport)
	PP( "listening port "<< remote_wantport)
	for(char i=0;;i+=16){
		lb(
			if(channel = libssh2_channel_forward_accept(listener))								x->put(channel);
			else if(!i&&(libssh2_session_last_errno(session)-LIBSSH2_ERROR_EAGAIN))				goto shutdown;
		)
		sleep05
	}
shutdown:
	PP("closing")
	libssh2_session_set_blocking(session, 1);
	PP(libssh2_channel_forward_cancel(listener))
	PP(libssh2_session_disconnect(session, "Client disconnecting normally"))
	PP(libssh2_session_free(session))
	if(++ec<5 && ++ec2<26){
		Sleep(ec*2605);
		PP(" retry "<<ec)
		L_RELEASE
		goto retry;
	}
	PP( " bye " )
	libssh2_exit();
	return 0;
}