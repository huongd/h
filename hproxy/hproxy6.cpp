//		g++ -I/root/h/i -pthread -s -O3 -Os -Wfatal-errors -fpermissive %.cpp -o %.eol ; upx %.eol
//		g++.exe -Id:/h/i -pthread -s -O3 -Os -Wfatal-errors -fpermissive %.cpp -o %.exe -lws2_32 ; upx.exe %.exe
//		cl %.cpp /Ox /W3 /EHsc
//		++		lock macro
//		./%.exe mn4w0gYaru0obq4
// 		hproxy PORT PRINT const|min maxthread
//             5555 1     26        _
#include "hnet.h"
#include "hthread.h"

#define MAXPENDING 200
#define BUF_SIZE 4096
#define PP(x) if(PRINT) cout << x <<endl ;
int PRINT=1;
static void copyloop(int fd1, int fd2, char *buf ) {
	unsigned long rc;
	int n, c=0;
	while(c++<86) {
		if sock_rc(fd1) {
			if((n = recv(fd1, buf, BUF_SIZE, 0))<1) return;
			if(send(fd2, buf, n, 0)<1) return;
			c=0;
		}
		if sock_rc(fd2) {
			if((n = recv(fd2, buf, BUF_SIZE, 0))<1) return;
			if(send(fd1, buf, n, 0)<1) return;
			c=0;
		}
		if(c) sleep1
		sleep001
	}
}
bool s2(SOCK src, long ip, short port, char* buf, char *d1=0, char *d2=0, int len1=0, int len2=0 ){
	if(PRINT){
		L_ACQUIRE
		if (buf[0]<26)	cout << " client "<< peer_ip(src)<< "  [socks"<< 0+buf[0];
		else			cout << " client "<< peer_ip(src)<< "  ["<< buf[0]<<buf[1]<<buf[2]<<"   ";
		cout <<"]  connect to  "<< ip2str(ip) << "\t :  " << htons(port) << endl;
		L_RELEASE
	}
	SOCK dest = connect_host(ip, port);
	if (dest==SOCK_E)
		return 0;
	d1 && send(src , d1, len1, 0);
    d2 && send(dest, d2, len2, 0);
	copyloop(src, dest, buf);
	cns(dest)
	return 1;
}
bool s1(SOCK sock) {
	char buf[BUF_SIZE];
	long ip, len=recv(sock, buf, BUF_SIZE, 0);
	if(len<2||len==BUF_SIZE)		return 0;
	if(buf[0]==5){									//				SOCKS5
		buf[1]=0;
		send(sock, buf, 2, 0);
		if(recv(sock, buf, BUF_SIZE, 0)<9 || buf[3]-1 || buf[1]-1)			return 0;
		return s2( sock, *(long*)(buf+4), *(short*)(buf+8), buf, "\x5\x0\x0\x1huongd",0, 10);
	}else if(buf[0]==4)								//				SOCKS4
		return s2( sock, *(long*)(buf+4), *(short*)(buf+2), buf, "\x0Zhuongd"        ,0, 8);
	else{
		char * c, *path ;
		buf[len]=0;
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
void handle_connection(SOCK client ) {
    if(!s1(client)&&PRINT)
		cout << " client "<< peer_ip(client) << " [error ]  invalid protocol \n";
	cns(client)
}
int main(int argc, char **argv) 
{
	SOCK svsock , client;
	DECRYPTH
	if (argc>2)
		PRINT= atoi (argv[2]);
	PP( "\t\t hproxy \n Copyright huongdoanminh@gmail.com \n\n\n" )
    SOCKINIT
	svsock = server(INADDR_ANY, argc>1 ? atoi (argv[1]) : 5555, MAXPENDING);
	if(svsock == SOCK_E) {
		PP( "[-] Failed to create server" )
        return 1;
    }
	PP( "\t listening port "<< (argc>1 ? atoi (argv[1]) : 5555))
	if (argc>4){
		PP( " \t"<< argv[3]<<" -> "<<argv[4] << " threads in dynamic mode \n\n" )
		auto x = hpool(handle_connection, atoi (argv[3]), atoi (argv[4]));
		// while((client = accept(svsock, 0, 0)) > 0) x -> put(client);
		while(1) if((client = accept(svsock, 0, 0)) > 0)x -> put(client); else sleep1
	}else{
		PP( " \t"<< (argc>3?atoi(argv[3]):26) << " threads in static mode \n\n" )
		auto x = hspool(handle_connection, argc>3 ? atoi (argv[3]) : 26 );
		while(1) if((client = accept(svsock, 0, 0)) > 0)x -> put(client); else sleep1
	}	
}