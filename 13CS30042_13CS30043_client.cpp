// Assignment 3
// Developing a Reliable Transport Layer Protocol using Raw Sockets

// Objective
// The objective of this assignment is to develop a reliable transport layer protocol on the top of the IP layer.

// Group Details
// Member 1: Jeenu Grover (13CS30042)
// Member 2: Ashish Sharma (13CS30043)

// Filename: client.cpp -- Implementation of Client

#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/types.h>
#include <string.h>
#include <sstream>

using namespace std;


#define PCKT_LEN 8192
#define DATA_LEN 8100
#define SIZE_IP sizeof(struct iphdr)
#define TIMEVAL 5

// Header structure for RTLP -- 18 bytes (Actually SIZE is 20 NOT 18 because of rounding to multiples of 4.)
struct RLTPhdr
{
    unsigned short int sPort;
    unsigned short int dPort;
    unsigned int syn;
    unsigned int ack;
    unsigned int chkSum;
    unsigned short int option;// 0-SYN, 1-DATA, 2-FIN, 3-ACK(For SYN+ACK), 4-ACK(For FIN+ACK)
};

#define SIZE_RTLP sizeof(struct RLTPhdr)

// Function to compute checksum
unsigned int adler32(char *data, size_t len)
{
    const int MOD_ADLER = 65521;

    unsigned int a = 1, b = 0;
    size_t index;

    /* Process each byte of the data in order */
    for (index = 0; index < len; ++index)
    {
        a = (a + data[index]) % MOD_ADLER;
        b = (b + a) % MOD_ADLER;
    }

    return (b << 16) | a;
}

// Decoding the Checksum received
bool decode_checksum_new(char *buffer,int buflen)
{
    struct RLTPhdr *RTL = (struct RLTPhdr *)(buffer+SIZE_IP);
    char *new_buffer = new char[buflen];
    unsigned int temp = RTL->chkSum;
    RTL->chkSum = 0;
    unsigned int val = adler32(buffer+SIZE_IP,buflen-SIZE_IP);
    //cout<<"CheckSum received is : "<<val<<endl;

    RTL->chkSum = temp;
    return (val == temp);
}

// Common Function For Sending Packet to Server
void syn(int sd,char sip[], char destip[],int sp,int dp,const char msg[],int SYN,int ACK,int option)
{
    char buffer[PCKT_LEN];
    memset(buffer,0,PCKT_LEN);


    struct iphdr ip;
    struct RLTPhdr rltp;


    struct sockaddr_in sin,din;
    sin.sin_family = AF_INET;
    din.sin_family = AF_INET;
    sin.sin_port = 0;//###
    din.sin_port = 0;//###

    inet_pton(AF_INET,sip,(struct in_addr *)&sin.sin_addr.s_addr);
    inet_pton(AF_INET,destip,(struct in_addr *)&din.sin_addr.s_addr);

    // Set the IP Header Parameters
    ip.ihl = 5;
    ip.version = 4;
    ip.tos = 16; // Low delay
    ip.tot_len = sizeof(struct iphdr) + sizeof(struct RLTPhdr) + strlen(msg); //###

    ip.frag_off = 0;
    ip.ttl = 64; // hops
    ip.protocol = IPPROTO_RAW;
    ip.saddr = sin.sin_addr.s_addr;
    ip.daddr = din.sin_addr.s_addr;
    ip.check = 0; //####

    memcpy(buffer,(char*)&ip,sizeof(ip));

    // Set the RTLP Header Parameters
    rltp.sPort = 0;//htons(atoi(argv[2])); //###
    rltp.dPort = 0;//htons(atoi(argv[4])); //###
    rltp.syn = htonl(SYN);
    rltp.ack = htonl(ACK);
    rltp.chkSum = 0;
    rltp.option = option; // 0-SYN 1-DATA 2-FIN 3-ACK( for ACK+SYN) 4-ACK(for ACK-FIN)
    memcpy(buffer+ sizeof(struct iphdr),&rltp,sizeof(rltp));
    // Copy the Msg in the buffer
    memcpy(buffer + sizeof(struct  iphdr) + sizeof(rltp), msg,strlen(msg) );

    // Compute the CheckSum
    rltp.chkSum = adler32(buffer+sizeof(iphdr),ip.tot_len-sizeof(iphdr));
    
    memcpy(buffer+ sizeof(struct iphdr),&rltp,sizeof(rltp));
    memcpy(buffer + sizeof(struct  iphdr) + sizeof(rltp), msg,strlen(msg) );

    struct RLTPhdr * bla = (struct RLTPhdr *)(buffer + 20);
    struct iphdr * ipl = (struct iphdr * )buffer;
    cout<<"CheckSum sent: "<<rltp.chkSum<<" Length : "<<(unsigned int)ipl->tot_len<<endl;
    //cout <<"Length of msg sent is : " << (unsigned int)ipl->tot_len<<endl;;

    //printf("Using::Source IP: %s port: %d, Target IP: %s port: %d.\n", sip, sp,destip, dp);
    // Send the Packet
    cout<<"\ns1 : "<<SYN<<" s2 : "<<ACK<< endl;
    if(sendto(sd, buffer, ip.tot_len, 0, (struct sockaddr *)&din, (socklen_t)sizeof(din)) < 0)
    {
        perror("sendto() error");
        exit(-1);
    }
    else
        cout<<"Successfully sent to :"<<destip<<endl;
    //sleep(1);


}


// Send DATA and get the Acknowledgement back from Server
void send_data(int sd,char sip[], char destip[],int sp,int dp,const char msg[],int *seq_no,int *ack_no,int option)
{
    struct sockaddr_in saddr;
    saddr.sin_family = AF_INET;
    saddr.sin_port = 0;
    inet_pton(AF_INET,destip,(struct in_addr *)&saddr.sin_addr.s_addr);
    int saddr_len = sizeof(saddr);
    int buflen;
    char * output = new char[PCKT_LEN];

    //int SYN = 2,ACK = 0;

    fd_set reader;
    
    struct  timeval timeout;
    timeout.tv_sec = TIMEVAL;
    timeout.tv_usec = 0;

    *seq_no = *seq_no+strlen(msg);
    int ac = -1,sy = -1;
    RLTPhdr * RTL;


    while(1)
    {
        int SYN = *seq_no;
        int ACK = *ack_no;
        syn(sd,sip,destip,sp,dp,msg,SYN,ACK,option); //###
        //cout<<"ENTER 1"<<endl;

        timeout.tv_sec = TIMEVAL;
        timeout.tv_usec = 0;
        FD_ZERO(&reader);
        FD_SET(sd,&reader);


        if( select(FD_SETSIZE,&reader,NULL,NULL,&timeout) > 0)
        {
            //cout<<"ENTER 2"<<endl;
            if(FD_ISSET(sd,&reader))
            {
                //cout<<"ENTER 3"<<endl;
                buflen=recvfrom(sd,output,PCKT_LEN,0,(struct sockaddr *)(&saddr),(socklen_t *)&saddr_len);
                if(buflen<0)
                {
                    //cout<<"ENTER 4"<<endl;
                    printf("error in reading recvfrom function\n");
                    continue;
                }

                RTL = (struct RLTPhdr *)(output+20);
                ac = ntohl(RTL->syn);
                sy = ntohl(RTL->ack);

                *seq_no = sy;
                *ack_no = ac;
                cout<<"\ns1 : "<<ac<<" s2 : "<<sy<<" Bytes Received : "<<buflen<< endl;
                cout<<"Message Recieved:  "<<output+ SIZE_IP+SIZE_RTLP<<endl;
                if(sy != SYN || !decode_checksum_new(output,buflen))continue;
                //cout<<"ENTER 6"<<endl;
                break;
            }
            else continue;
        }
        else continue;

    }



}

// Establish Connection With the Server via 3-Way Handshaking Mechanism
void client_con_est(int sd,char sip[], char destip[],int sp,int dp,const char msg[],int *seq_no,int *ack_no)
{
    struct sockaddr_in saddr;
    saddr.sin_family = AF_INET;
    saddr.sin_port = 0;
    inet_pton(AF_INET,destip,(struct in_addr *)&saddr.sin_addr.s_addr);
    int saddr_len = sizeof(saddr);
    int buflen;
    char * output = new char[PCKT_LEN];

    int SYN = 2,ACK = 0;

    fd_set reader;
    
    struct  timeval timeout;
    timeout.tv_sec = TIMEVAL;
    timeout.tv_usec = 0;


    int ac = -1,sy = -1;
    RLTPhdr * RTL;


    while(1)
    {
        // Do Until connection is established Successfully

        // Send SYN Request
        syn(sd,sip,destip,sp,dp,msg,SYN,ACK,0); //###
        //cout<<"ENTER 1"<<endl;

        timeout.tv_sec = TIMEVAL;
        timeout.tv_usec = 0;
        FD_ZERO(&reader);
        FD_SET(sd,&reader);


        if( select(FD_SETSIZE,&reader,NULL,NULL,&timeout) > 0)
        {
            //cout<<"ENTER 2"<<endl;
            if(FD_ISSET(sd,&reader))
            {
                //cout<<"ENTER 3"<<endl;
                // Receive SYN+ACK
                buflen=recvfrom(sd,output,PCKT_LEN,0,(struct sockaddr *)(&saddr),(socklen_t *)&saddr_len);
                if(buflen<0)
                {
                    //cout<<"ENTER 4"<<endl;
                    printf("error in reading recvfrom function\n");
                    continue;
                }

                RTL = (struct RLTPhdr *)(output+20);
                ac = ntohl(RTL->syn);
                sy = ntohl(RTL->ack);
                cout<<"\ns1 : "<<ac<<" s2 : "<<sy<<" Bytes Received : "<<buflen<< endl;
                cout<<"Message Received:  "<<output+SIZE_RTLP+SIZE_IP<<endl;
                if(sy != SYN || !decode_checksum_new(output,buflen))continue;
                //cout<<"ENTER 6"<<endl;
                *seq_no = SYN;
                *ack_no = ac;
                // Send ACK
                syn(sd,sip,destip,sp,dp,msg,SYN,ac,3);
                break;
            }
            else continue;
        }
        else continue;

    }


}

// Terminate Connection With the Server via 3-Way Handshaking Mechanism
void client_con_end(int sd,char sip[], char destip[],int sp,int dp,const char msg[],int *seq_no,int *ack_no)
{
    struct sockaddr_in saddr;
    saddr.sin_family = AF_INET;
    saddr.sin_port = 0;
    inet_pton(AF_INET,destip,(struct in_addr *)&saddr.sin_addr.s_addr);
    int saddr_len = sizeof(saddr);
    int buflen;
    char * output = new char[PCKT_LEN];

    //int SYN = 2,ACK = 0;

    fd_set reader;
    
    struct  timeval timeout;
    timeout.tv_sec = TIMEVAL;
    timeout.tv_usec = 0;


    int ac = -1,sy = -1;
    RLTPhdr * RTL;


    while(1)
    {
        // Do Until connection is terminated Successfully

        // Send FIN Request
        int SYN = *seq_no;
        int ACK = *ack_no;
        syn(sd,sip,destip,sp,dp,msg,SYN,ACK,2); //###
        //cout<<"ENTER 1"<<endl;

        timeout.tv_sec = TIMEVAL;
        timeout.tv_usec = 0;
        FD_ZERO(&reader);
        FD_SET(sd,&reader);


        if( select(FD_SETSIZE,&reader,NULL,NULL,&timeout) > 0)
        {
            //cout<<"ENTER 2"<<endl;
            if(FD_ISSET(sd,&reader))
            {
                //cout<<"ENTER 3"<<endl;
                // Receive FIN+ACK
                buflen=recvfrom(sd,output,PCKT_LEN,0,(struct sockaddr *)(&saddr),(socklen_t *)&saddr_len);
                if(buflen<0)
                {
                    //cout<<"ENTER 4"<<endl;
                    printf("error in reading recvfrom function\n");
                    continue;
                }

                RTL = (struct RLTPhdr *)(output+20);
                ac = ntohl(RTL->syn);
                sy = ntohl(RTL->ack);
                cout<<"\ns1 : "<<ac<<" s2 : "<<sy<<" Bytes Received : "<<buflen<< endl;
                cout<<"Message Received:  "<<output+SIZE_IP+SIZE_RTLP<<endl;
                if(sy != SYN || !decode_checksum_new(output,buflen))continue;
                //cout<<"ENTER 6"<<endl;
                *seq_no = SYN;
                *ack_no = ac;
                // Send ACK
                syn(sd,sip,destip,sp,dp,msg,SYN,ac,4);
                break;
            }
            else continue;
        }
        else continue;

    }

}


int main(int argc, char * argv[])
{
    printf("\033[H\033[J");
    //cout<<"vv " <<sizeof(struct RLTPhdr)<<" "<<sizeof(struct iphdr)<<endl;

    int sd =  socket(AF_INET,SOCK_RAW,IPPROTO_RAW);
    if(sd < 0)cout<<"Socket Error\n";

    int seq_no,ack_no;

    int on = 1;
    if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
    {
        perror("setsockopt");
        exit(1);
    }

    // Establish Connection With Server
    client_con_est(sd,argv[1],argv[3],atoi(argv[2]),atoi(argv[4]),"Connection Request",&seq_no,&ack_no);

    cout<<"Connection Established"<<endl;

    cout<<"Seq_no: "<<seq_no<<" ack_no: "<<ack_no<<endl;

    while(1)
    {
        int in;
        cout<<"\n\nEnter 1 to send echo request"<<endl;
        cout<<"Enter 2 to terminate the connection"<<endl;


        cin>>in;

        if(in==1)
        {
            // Send ECHO Request
            int no;
            cout<<"Enter a number to echo: "<<endl;
            cin>>no;
            char msg[DATA_LEN];
            strcpy(msg,"");
            stringstream ss;
            ss<<"ECHO REQ "<<no;
            strcpy(msg,ss.str().c_str());
            cout<<"Sent Message:"<<msg<<endl;
            send_data(sd,argv[1],argv[3],atoi(argv[2]),atoi(argv[4]),msg,&seq_no,&ack_no,1);
        }
        else if(in==2)
        {
            // Send FIN Request
            client_con_end(sd,argv[1],argv[3],atoi(argv[2]),atoi(argv[4]),"Termination Request",&seq_no,&ack_no);
            cout<<"Connection successfully Terminated"<<endl;
            cout<<"Quiting"<<endl;
            exit(1);
        }
    }
    return 0;
}
