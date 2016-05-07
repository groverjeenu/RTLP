// Assignment 3
// Developing a Reliable Transport Layer Protocol using Raw Sockets

// Objective
// The objective of this assignment is to develop a reliable transport layer protocol on the top of the IP layer.

// Group Details
// Member 1: Jeenu Grover (13CS30042)
// Member 2: Ashish Sharma (13CS30043)

// Filename: server.cpp -- Implementation of Server

#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <iomanip>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define MAX_PACKET_LEN 8192
#define MAX_DATA_LEN 8100

using namespace std;

#define SIZE_IP sizeof(iphdr)

// Header structure for RTLP -- 18 bytes (Actually SIZE is 20 NOT 18 because of rounding to multiples of 4.)
typedef struct RLTPhdr
{
    unsigned short int sPort;
    unsigned short int dPort;
    unsigned int syn;
    unsigned int ack;
    unsigned int chkSum;
    unsigned short int option;	// 0-SYN, 1-DATA, 2-FIN, 3-ACK(For SYN+ACK), 4-ACK(For FIN+ACK)
} RTLP_Header;


#define SIZE_RLTP sizeof(RTLP_Header)


// Function to compute checksum
unsigned int adler32(char *data, size_t len)
{
    const int MOD_ADLER = 65521;

    unsigned int a = 1, b = 0;
    size_t index;

    /* Process each byte of the data in order */
    for (index = 0; index < len; ++index)
    {
        //cout<<"Here "<<index<<endl;
        a = (a + data[index]) % MOD_ADLER;
        b = (b + a) % MOD_ADLER;
    }

    return (b << 16) | a;
}

// Decoding the Checksum received
bool decode_checksum_new(char *buffer,int buflen)
{
    //int buflen = sizeof(buffer);
    RTLP_Header *RTL = (RTLP_Header *)(buffer+SIZE_IP);
    char *new_buffer = new char[buflen];
    unsigned int temp = RTL->chkSum;
    RTL->chkSum = 0;
    unsigned int val = adler32(buffer+SIZE_IP,buflen-SIZE_IP);

    RTL->chkSum = temp;
    //cout<<"ch: "<<val<<endl;
    return (val == temp);
}

// Send the Acknowledgement of the received data
void send_ACK(int servfd,char *src_IP,char *dest_IP,int ack_no,RTLP_Header *RTL,char *msg)
{
    char new_msg_1[MAX_DATA_LEN];
    char new_msg_2[MAX_DATA_LEN];

    // Extract the ECHO REQ Number
    int i = 0;
    while(msg[i]!=' ')
    {
        i++;
    }
    i++;

    while(msg[i]!=' ')
    {
        i++;
    }
    i++;

    int j = 0;
    while(msg[i]!='\0')
    {
        new_msg_1[j] = msg[i];
        i++;
        j++;
    }
    new_msg_1[j] = '\0';

    int no1 = atoi(new_msg_1);

    no1++;

    stringstream out;
    out<<"ECHO RES "<<(no1);
    strcpy(new_msg_2,out.str().c_str());
    cout<<"Message sent as ACK: "<<new_msg_2<<endl;
    char buffer[MAX_PACKET_LEN];
    memset(buffer,0,MAX_PACKET_LEN);

    struct iphdr ip;
    RTLP_Header rltp;
    int seq_no = ntohl(RTL->syn);

    struct sockaddr_in sin,din;
    sin.sin_family = AF_INET;
    din.sin_family = AF_INET;
    sin.sin_port = 0;
    din.sin_port = 0;

    inet_pton(AF_INET,src_IP,(struct in_addr *)&sin.sin_addr.s_addr);
    inet_pton(AF_INET,dest_IP,(struct in_addr *)&din.sin_addr.s_addr);


    // Set the IP Header Parameters
    ip.ihl = 5;
    ip.version = 4;
    ip.tos = 16; // Low delay
    ip.tot_len = sizeof(struct iphdr)+sizeof(struct RLTPhdr)+strlen(new_msg_2); //###

    ip.frag_off = 0;
    ip.ttl = 64; // hops
    ip.protocol = IPPROTO_RAW;
    ip.saddr = sin.sin_addr.s_addr;
    ip.daddr = din.sin_addr.s_addr;
    ip.check = 0;

    memcpy(buffer,(char*)&ip,sizeof(ip));

    // Set the RTLP Header Parameters
    rltp.sPort = 0;
    rltp.dPort = 0;
    rltp.syn = htonl(ack_no+strlen(new_msg_2));
    rltp.ack = htonl(seq_no);
    rltp.chkSum = 0;
    memcpy(buffer+ sizeof(struct iphdr),&rltp,sizeof(rltp));

    // Copy the Msg in the buffer
    memcpy(buffer + sizeof(struct  iphdr) + sizeof(rltp), new_msg_2,strlen(new_msg_2));

    // Compute the CheckSum
    rltp.chkSum = adler32(buffer+sizeof(struct  iphdr),sizeof(rltp)+strlen(new_msg_2));
    memcpy(buffer+ sizeof(struct iphdr),&rltp,sizeof(rltp));
    memcpy(buffer + sizeof(struct  iphdr) + sizeof(rltp), new_msg_2,strlen(new_msg_2));
    //printf("Using::Source IP: %s port: %d, Target IP: %s port: %d.\n", src_IP, src_port,dest_IP, dest_port);


    // Send the Packet
    if(sendto(servfd, buffer, ip.tot_len, 0, (struct sockaddr *)&din, (socklen_t)sizeof(din)) < 0)
    {
        perror("sendto() error");
        exit(-1);
    }
    else
        cout<<"Successfully sent to :"<<dest_IP<<endl;

}


// Send SYN+ACK for Accepting Connection request
void send_SYN_ACK(int servfd,char *src_IP, char *dest_IP,int seq_no,int send_seq)
{
    char buffer[MAX_PACKET_LEN];
    memset(buffer,0,MAX_PACKET_LEN);

    struct iphdr ip;
    RTLP_Header rltp;

    struct sockaddr_in sin,din;
    sin.sin_family = AF_INET;
    din.sin_family = AF_INET;
    sin.sin_port = 0;
    din.sin_port = 0;

    inet_pton(AF_INET,src_IP,(struct in_addr *)&sin.sin_addr.s_addr);
    inet_pton(AF_INET,dest_IP,(struct in_addr *)&din.sin_addr.s_addr);


    // Set the IP Header Parameters
    ip.ihl = 5;
    ip.version = 4;
    ip.tos = 16; // Low delay
    ip.tot_len = sizeof(struct iphdr) + sizeof(struct RLTPhdr); //###

    ip.frag_off = 0;
    ip.ttl = 64; // hops
    ip.protocol = IPPROTO_RAW;
    ip.saddr = sin.sin_addr.s_addr;
    ip.daddr = din.sin_addr.s_addr;
    ip.check = 0;

    memcpy(buffer,(char*)&ip,sizeof(ip));

    // Set the RTLP Header Parameters
    rltp.sPort = 0;
    rltp.dPort = 0;
    rltp.syn = htonl(send_seq);
    rltp.ack = htonl(seq_no);
    rltp.chkSum = 0;
    memcpy(buffer+ sizeof(struct iphdr),&rltp,sizeof(rltp));

    // Compute the CheckSum
    rltp.chkSum = adler32(buffer+sizeof(struct  iphdr),sizeof(rltp));
    memcpy(buffer+ sizeof(struct iphdr),&rltp,sizeof(rltp));

    //printf("Using::Source IP: %s port: %d, Target IP: %s port: %d.\n", src_IP, src_port,dest_IP, dest_port);

    // Send the Packet
    if(sendto(servfd, buffer, ip.tot_len, 0, (struct sockaddr *)&din, (socklen_t)sizeof(din)) < 0)
    {
        perror("sendto() error");
        exit(-1);
    }
    else
        cout<<"Successfully sent to :"<<dest_IP<<endl;
}

// Receive the SYN Request
void receive_SYN(int servfd,char *src_IP,int send_seq,int *seq_no,int *ack_no)
{
    struct iphdr *IP;
    RTLP_Header *RTL;
    char *dest_IP = new char[100];
    // Receive SYN From Client
    char *output;
    int prev = -1,cnt = 0;

    while(1)
    {
        // Receive until 3-Way Handshake has completed successfully
        output = new char[MAX_PACKET_LEN];

        struct sockaddr_in saddr;

        int saddr_len = sizeof(saddr);

        // Receive the message
        int buflen=recvfrom(servfd,output,MAX_PACKET_LEN,0,(struct sockaddr *)(&saddr),(socklen_t *)&saddr_len);

        if(buflen<0)
        {
            printf("error in reading recvfrom function\n");
            return;
        }

        RTL = (RTLP_Header *)(output+SIZE_IP);

        IP = (struct iphdr *)(output);
        //cout<<"iphg :"<<(unsigned int)IP->tot_len<<endl;

        // Get the IP of Sender from IP Header
        inet_ntop(AF_INET, &(IP->saddr), dest_IP, INET_ADDRSTRLEN);
        //cout<<"Successfully Received "<<buflen<<": "<<output+SIZE_IP+SIZE_RLTP<<" SEQ: "<<ntohl(RTL->syn)<<" ACK: "<<ntohl(RTL->ack)<<"  chkSum: "<<RTL->chkSum<<endl;
        // Do Checksum Check
        if(decode_checksum_new(output,buflen))
        {
            // Print the data
            cout<<"Successfully Received "<<buflen<<": "<<output+SIZE_IP+SIZE_RLTP<<" SEQ: "<<ntohl(RTL->syn)<<" ACK: "<<ntohl(RTL->ack)<<"  chkSum: "<<RTL->chkSum<<endl;
            prev = RTL->syn;
        }
        else continue;
        if(RTL->option != 0) continue;
        fd_set read_fd_set;

        FD_ZERO(&read_fd_set);
        FD_SET(servfd, &read_fd_set);
        struct timeval tv;

        tv.tv_sec = 5;

        // Extract RTLP_Header
        RTL = (RTLP_Header *)(output+SIZE_IP);

        // Send SYN+ACK
        send_SYN_ACK(servfd,src_IP,dest_IP,ntohl(RTL->syn),send_seq);

        // Wait for ACK till timeout -- If Expired repeat the process again
        if(select(4, &read_fd_set, NULL, NULL, &tv) > 0)
        {
            if(FD_ISSET(servfd, &read_fd_set))
            {
                output = (char *)malloc(MAX_PACKET_LEN*sizeof(char));

                int saddr_len = sizeof(saddr);

                // Receive the message
                int buflen=recvfrom(servfd,output,MAX_PACKET_LEN,0,(struct sockaddr *)(&saddr),(socklen_t *)&saddr_len);

                //if(decode_checksum_new(output,buflen))

                if(buflen<0)
                {
                    printf("error in reading recvfrom function\n");
                    return;
                }
                else
                {
                    RTL = (RTLP_Header *)(output+SIZE_IP);
                    cout<<"Successfully Received "<<buflen<<": "<<output+SIZE_IP+SIZE_RLTP<<" SEQ: "<<ntohl(RTL->syn)<<" ACK: "<<ntohl(RTL->ack)<<"  chkSum: "<<RTL->chkSum<<endl;
                    if(RTL->option != 3) continue;
                    *seq_no = ntohl(RTL->syn);
                    *ack_no = ntohl(RTL->ack);
                    break;
                }
            }

        }


        else continue;
    }
}


// Send SYN+ACK for Accepting Connection request
void send_FIN_ACK(int servfd,char *src_IP, char *dest_IP,int seq_no,int send_seq)
{
    cout<<"dest_IPnew: "<<dest_IP<<endl;
    char buffer[MAX_PACKET_LEN];
    memset(buffer,0,MAX_PACKET_LEN);

    struct iphdr ip;
    RTLP_Header rltp;

    struct sockaddr_in sin,din;
    sin.sin_family = AF_INET;
    din.sin_family = AF_INET;
    sin.sin_port = 0;
    din.sin_port = 0;

    inet_pton(AF_INET,src_IP,(struct in_addr *)&sin.sin_addr.s_addr);
    inet_pton(AF_INET,dest_IP,(struct in_addr *)&din.sin_addr.s_addr);

    // Set the IP Header Parameters
    ip.ihl = 5;
    ip.version = 4;
    ip.tos = 16; // Low delay
    ip.tot_len = sizeof(struct iphdr) + sizeof(struct RLTPhdr); //###

    ip.frag_off = 0;
    ip.ttl = 64; // hops
    ip.protocol = IPPROTO_RAW;
    ip.saddr = sin.sin_addr.s_addr;
    ip.daddr = din.sin_addr.s_addr;
    ip.check = 0;

    memcpy(buffer,(char*)&ip,sizeof(ip));

    // Set the RTLP Header Parameters
    rltp.sPort = 0;
    rltp.dPort = 0;
    rltp.syn = htonl(send_seq);
    rltp.ack = htonl(seq_no);
    rltp.chkSum = 0;
    memcpy(buffer+ sizeof(struct iphdr),&rltp,sizeof(rltp));

    // Compute the CheckSum
    rltp.chkSum = adler32(buffer+sizeof(struct  iphdr),sizeof(rltp));
    memcpy(buffer+ sizeof(struct iphdr),&rltp,sizeof(rltp));

    //printf("Using::Source IP: %s port: %d, Target IP: %s port: %d.\n", src_IP, src_port,dest_IP, dest_port);

    // Send the Packet
    if(sendto(servfd, buffer, ip.tot_len, 0, (struct sockaddr *)&din, (socklen_t)sizeof(din)) < 0)
    {
        perror("sendto() error");
        exit(-1);
    }
    else
        cout<<"Successfully sent to :"<<dest_IP<<endl;
}

// Receive the FIN Request
void receive_FIN(int servfd,char *src_IP,char *dest_IP,int send_seq,int seq_no,int *ack_no)
{
    struct iphdr *IP;
    RTLP_Header *RTL;
    char *output;
    //char *dest_IP = (char *)malloc(100*sizeof(char));
	
    // Receive SYN From Client
    int prev = -1,cnt = 0;
    int flag = 0;

    while(1)
    {
        struct sockaddr_in saddr;

        int saddr_len = sizeof(saddr);

        if(flag != 0)
        {
            // Receive until 3-Way Handshake for Termination has completed successfully
            dest_IP = (char *)malloc(100*sizeof(char));
            output = (char *)malloc(MAX_PACKET_LEN*sizeof(char));

            // Receive the message
            int buflen=recvfrom(servfd,output,MAX_PACKET_LEN,0,(struct sockaddr *)(&saddr),(socklen_t *)&saddr_len);

            if(buflen<0)
            {
                printf("error in reading recvfrom function\n");
                return;
            }

            RTL = (RTLP_Header *)(output+SIZE_IP);
            IP = (struct iphdr *)(output);

            // Get the IP Of the Client
            inet_ntop(AF_INET, &(IP->saddr), dest_IP, INET_ADDRSTRLEN);

            // Do Checksum Check
            if(decode_checksum_new(output,buflen))
            {
                // Print the data
                cout<<"Succesfully Received "<<buflen<<": "<<output+SIZE_IP+SIZE_RLTP<<" SEQ: "<<ntohl(RTL->syn)<<" ACK: "<<ntohl(RTL->ack)<<"  chkSum: "<<RTL->chkSum<<endl;
                prev = RTL->syn;
                seq_no = RTL->syn;
            }
            else continue;

            if(RTL->option != 2) continue;

        }

        flag = 1;

        fd_set read_fd_set;

        FD_ZERO(&read_fd_set);
        FD_SET(servfd, &read_fd_set);
        struct timeval tv;

        tv.tv_sec = 5;

        // Extract RTLP_Header
        RTL = (RTLP_Header *)(output+SIZE_IP);

        cout<<"FIN+ACK"<<endl;

        // Send SYN+ACK
        send_FIN_ACK(servfd,src_IP,dest_IP,seq_no,send_seq);

        if(select(4, &read_fd_set, NULL, NULL, &tv) > 0)
        {
            if(FD_ISSET(servfd, &read_fd_set))
            {
                output = (char *)malloc(MAX_PACKET_LEN*sizeof(char));

                int saddr_len = sizeof(saddr);

                // Receive the message
                int buflen=recvfrom(servfd,output,MAX_PACKET_LEN,0,(struct sockaddr *)(&saddr),(socklen_t *)&saddr_len);

                //if(decode_checksum_new(output,buflen))

                if(buflen<0)
                {
                    printf("error in reading recvfrom function\n");
                    return;
                }
                else
                {
                    RTL = (RTLP_Header *)(output+SIZE_IP);
                    cout<<"Succesfully Received "<<buflen<<": "<<output+SIZE_IP+SIZE_RLTP<<" SEQ: "<<ntohl(RTL->syn)<<" ACK: "<<ntohl(RTL->ack)<<"  chkSum: "<<RTL->chkSum<<endl;
                    //*seq_no = ntohl(RTL->syn);
                    *ack_no = ntohl(RTL->ack);
                    if(RTL->option != 4) continue;
                    break;
                }
            }

        }


        else continue;
    }
}

// Function for Receiving the packets from client and taking required actions
void general_receive(int servfd,char *src_IP,int ack_no,int *seq_no,int *ack_no_1)
{
    struct iphdr *IP;
    RTLP_Header *RTL;
    char *dest_IP = (char *)malloc(100*sizeof(char));
    // Receive SYN From Client
    char *output;
    int cnt = 0;

    while(1)
    {
        output = new char[MAX_PACKET_LEN];

        struct sockaddr_in saddr;
        int saddr_len = sizeof(saddr);

        // Receive the message
        int buflen=recvfrom(servfd,output,MAX_PACKET_LEN,0,(struct sockaddr *)(&saddr),(socklen_t *)&saddr_len);

        if(buflen<0)
        {
            printf("error in reading recvfrom function\n");
            return;
        }
        // Do Checksum Computation

        RTL = (RTLP_Header *)(output+SIZE_IP);
        IP = (struct iphdr *)(output);

        int opt = RTL->option;

        inet_ntop(AF_INET, &(IP->saddr), dest_IP, INET_ADDRSTRLEN);
        
        if(decode_checksum_new(output,buflen))
        {
            // Print the data
            cout<<"Succesfully Received "<<buflen<<": "<<output+SIZE_IP+SIZE_RLTP<<" SEQ: "<<ntohl(RTL->syn)<<" ACK: "<<ntohl(RTL->ack)<<"  chkSum: "<<RTL->chkSum<<endl;
        }
        else continue;


        if(opt == 1)
        {
            // Recieve Data
            send_ACK(servfd,src_IP,dest_IP,ntohl(RTL->ack),RTL,output+SIZE_IP+SIZE_RLTP);
        }
        else if(opt == 2)
        {
            receive_FIN(servfd,src_IP,dest_IP,ntohl(RTL->ack),ntohl(RTL->syn),ack_no_1);
            break;
        }
    }
}

int main(int argc, char * argv[])
{
    int servfd,send_seq = 100;
    int temp = 1;

    int seq_no,ack_no;

    servfd = socket(AF_INET,SOCK_RAW,IPPROTO_RAW);
    if(servfd<0)
    {
        perror("Socket() error");
        exit(-1);
    }

    if(setsockopt(servfd,IPPROTO_IP,IP_HDRINCL,&temp,sizeof(temp)) < 0)
    {
        perror("setsockopt() error");
        exit(-1);
    }


    while(1)
    {
    	cout<<"Waiting for new Connection"<<endl;
        printf("\033[H\033[J");
		
		// receive a new Connection request
        receive_SYN(servfd,argv[1],send_seq,&seq_no,&ack_no);

        cout<<"New Connection Established"<<endl;

        cout<<"Seq_no: "<<seq_no<<"\tack_no: "<<ack_no<<endl;

		// Receive DATA or FIN from the client
        general_receive(servfd,argv[1],ack_no,&seq_no,&ack_no);
        cout<<"Connection Closed..."<<endl;
        cout<<"Do you want to continue(y/n): "<<endl;
        string s;
        cin>>s;

        if(s=="y" || s== "y\n") continue;
		
        else break;
    }

    return 0;
}
