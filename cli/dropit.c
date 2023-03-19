#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>  
#include <getopt.h>
#include <assert.h>
#include "../netfilter/firewall.h"

typedef char bool;
#define false 0
#define true 1

ban_status rules;
int idx;

//variant receive argument value
char *protocol = NULL;
char *jump = NULL;
char *sourceip = NULL;
char *destip = NULL;
char *sourceport = NULL;
char *destport = NULL;

//cli preparation
static const char short_options [] = "p:j:s:d:fhlz:x:";
static const struct option long_options [] = {
	{ "protocol",   required_argument,      NULL,           'p' },
	{ "jump",       required_argument,      NULL,           'j' },
	{ "source",     required_argument,      NULL,           's' },
	{ "dest",       required_argument,      NULL,           'd' },
	{ "flush",      no_argument,            NULL,           'f' },
	{ "help",       no_argument,            NULL,           'h' },
	{ "list",       no_argument,            NULL,           'l' },
	{ "sourceport", required_argument,      NULL,           'z' },
	{ "destport",   required_argument,      NULL,           'x' },
	{ 0, 0, 0, 0 }
};

void cli(int rec, int sockfd, socklen_t len, int argc, char *argv[]);
static void print_usage(FILE *fp,int argc,char *argv[]);
void get_status();
void flush(int sockfd, socklen_t len);

void block_ICMP_in(int sockfd, socklen_t len);
void block_TCP_in(int sockfd, socklen_t len);
void block_UDP_in(int sockfd, socklen_t len);
void block_IP_in(int sockfd, socklen_t len);
void block_IP_out(int sockfd, socklen_t len);
void block_port_in(int sockfd, socklen_t len);
void block_port_out(int sockfd, socklen_t len);

void rules_detail(int sockfd, socklen_t len);
void printErr(char *msg){
    printf("%s error %d: %s\n",msg, errno, strerror(errno));
}

void deal_file(){
	FILE *fin, *fout;
    fin = fopen( "dropit.log", "r" );
    if(fin){
        fscanf(fin,"%d", &idx ); //read data from file
        fclose(fin);
    }else
        printErr("READ_FILE_ERROR!\n");
    // printf("%d\n",idx);
    idx -- ;
    fout = fopen("dropit.log","w");
    if(fout){
        fprintf(fout, "%d", idx);
        fclose(fout);
    }
    else
        printErr("open_file_error!\n");
}

int strcmp(const char *str1,const char *str2){
    while(*str1 == *str2){
        assert((str1 != NULL) && (str2 != NULL));       
        if(*str1 == '\0')
            return 0;
        str1++;
        str2++;
    }
    return *str1 - *str2;
}

char *lower(char *str){
    char *orign=str;
    for (; *str!='\0'; str++)
        *str = tolower(*str);
    return orign;
}


//need test!!!!!!!
bool ip_vaild_check(const char *ip){
    int dots = 0; /*字符.的个数*/
    int setions = 0; /*ip每一部分总和（0-255）*/
    if (NULL == ip || *ip == '.') /*排除输入参数为NULL, 或者一个字符为'.'的字符串*/
        return false;
    while (*ip) {
        if(*ip == '.'){
            dots ++;
            if(setions >= 0 && setions <= 255){ /*检查ip是否合法*/
                setions = 0;
                ip++;
                continue;
			}
            return false;
        }
        else if(*ip >= '0' && *ip <= '9'){ /*判断是不是数字*/
            setions = setions * 10 + (*ip - '0'); /*求每一段总和*/
        }else
            return false;
        ip++;
    }
//判断IP最后一段是否合法
    if(setions >= 0 && setions <= 255){
        if(dots == 3)
            return true;
    }
    return false;
}

bool port_vaild_check(const char* port){
	int p = atoi(port);
	if(p >= 0 && p <= 65535)
		return true;
	return false;
}


int main(int argc, char* argv[]){
	deal_file();
    int sockfd;
	socklen_t len;
    
	if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1)
		printErr("socket_Error!\n");
	else{
		len = sizeof(rules);
		if(getsockopt(sockfd, IPPROTO_IP, NOWRULE, (void *)&rules, &len))
			printErr("getsockopt_Error!\n");
		else{
			int rec = 0;
            while(rec != -1){
                int index = 0;
				int flag = 0;
                rec = getopt_long(argc, argv, short_options, long_options, &index);
			    cli(rec, sockfd, len, argc, argv);
            }
            // according to the value get , find rules
            rules_detail(sockfd, len);
		}
	}
    return 0;
}

void cli(int rec, int sockfd, socklen_t len, int argc, char *argv[]){
	bool ip_check;
	bool port_check;
    switch(rec){
        case 0:
            break;
        case 'p':
            protocol = optarg;
			protocol = lower(protocol);
            // printf("%s\n", protocol);
            break;
        case 'j':
            jump = optarg;
			jump = lower(jump);
            // printf("%s\n", jump);
            break;
        case 's':
            sourceip = optarg;
			//need test
			ip_check = ip_vaild_check(sourceip);
			if(ip_check == false){
				printf("IP INVAILD!\n");
				exit(EXIT_FAILURE);
			}
			// sourceip = lower(sourceip);
            // printf("%s\n", sourceip);
            break;
        case 'd':
            destip = optarg;
			// destip = lower(destip);
			ip_check = ip_vaild_check(destip);
			if(ip_check == false){
				printf("IP INVAILD!\n");
				exit(EXIT_FAILURE);
			}
            // printf("%s\n", destip);
            break;
        case 'f':
            flush(sockfd, len);
            exit(EXIT_SUCCESS);
        case 'h':
            print_usage(stderr, argc, argv);
            exit(EXIT_SUCCESS);
        case 'l':
            get_status();
            exit(EXIT_SUCCESS);
        //bug
        case 'z':
            sourceport = optarg;
			port_check = port_vaild_check(sourceport);
			if(port_check == false){
				printf("PORT INVAILD!\n");
				exit(EXIT_FAILURE);
			}
            // printf("%s\n", sourceport);
            break;
        case 'x':
            destport = optarg;
			port_check = port_vaild_check(destport);
			if(port_check == false){
				printf("PORT INVAILD!\n");
				exit(EXIT_FAILURE);
			}
            // printf("%s\n", destport);
            break;
		default:
			// print_usage(stderr, argc, argv);
			// exit(EXIT_FAILURE);
			// printf("\n");
			break;
	}
}


static void print_usage(FILE *fp, int argc, char *argv[]){
    fprintf(fp,
        "Usage: %s [options]\n"
        "[Options]:\n"
        "-p | --protocol name       Protocol need to filter\n"
        "-j | --jump drop/DROP      Specify the target of the rule\n"
        "-s | --source address      Source address need to filter\n"
        "-d | --dest address        Destination address need to filter\n"
        "-f | --flush               Flush the rules existed\n"
        "-h | --help                Print help message\n"
        "-l | --list                List rules existed\n"
        "-z | --sourceport port     Source port need to filter\n"
        "-x | --destport port       Destination port need to filter\n"
		"[Examples]:\n"
		"%s 	-s 8.8.8.8 -j drop\n"
		"		-d 8.8.8.8 -j drop\n"
		"		-p tcp -j drop\n"
		" 		-z 53 -j drop\n"
		"		-x 53 -j drop\n"
		" ",
        argv[0], argv[0]);
}

void get_status(){
		int i;
		printf("[current firewall status]:\n");
		//ICMP
		if(rules.icmp_status == 1)
			printf("PING STATUS: DROP\n");
		else
			printf("PING STATUS: ALLOW\n");
		
		//TCP
		if(rules.tcp_status == 1)
			printf("TCP STATUS: DROP\n");
		else
			printf("TCP STATUS: ALLOW\n");
		
		//UDP
		if(rules.udp_status == 1)
			printf("UDP STATUS: DROP\n");
		else
			printf("UDP STATUS: ALLOW\n");
		
		//source IP
		if(rules.source_ip_status != 0){
			for(i = 0;i <= MAX -1;i++){
				// !!maybe dont need anymore
				if(rules.ban_source_ip_list[i] == 0)
					continue;
				printf("SOURCE IP DROP:%d.%d.%d.%d\n", 
					(rules.ban_source_ip_list[i] & 0x000000ff) >> 0,
					(rules.ban_source_ip_list[i] & 0x0000ff00) >> 8,
					(rules.ban_source_ip_list[i] & 0x00ff0000) >> 16,
					(rules.ban_source_ip_list[i] & 0xff000000) >> 24);
			}
		}else{
			printf("SOURCE IP ALL ALLOWED\n");
			//rules.ip_status = MAX + 1;
		}

		//dest IP
		if(rules.dest_ip_status != 0){
			for(i = 0;i <= MAX - 1;i++){
				// !!maybe dont need anymore
				if(rules.ban_dest_ip_list[i] == 0)
					continue;
				printf("DESTINATION IP DROP:%d.%d.%d.%d\n", 
					(rules.ban_dest_ip_list[i] & 0x000000ff) >> 0,
					(rules.ban_dest_ip_list[i] & 0x0000ff00) >> 8,
					(rules.ban_dest_ip_list[i] & 0x00ff0000) >> 16,
					(rules.ban_dest_ip_list[i] & 0xff000000) >> 24);
			}
		}else{
			printf("DESTINATION IP ALL ALLOWED\n");
			//rules.ip_status = MAX + 1;
		}

		//source port
		if(rules.source_port_status != 0){
			for(i = 0;i <= MAX - 1;i++){
				// !!maybe dont need anymore
				if(rules.ban_source_port_list[i] == 0)
					continue;
				printf("SOURCE PORT DROP: %hu\n", rules.ban_source_port_list[i]);
			}
		}
		else{
			printf("SOURCE PORT ALL ALLOWED\n");
			//rules.port_status = MAX + 1;
		}

		//dest port
		if(rules.dest_port_status != 0){
			for(i = 0;i <= MAX - 1;i++){
				// !!maybe dont need anymore
				if(rules.ban_dest_port_list[i] == 0)
					continue;
				printf("DESTINATION PORT DROP: %hu\n", rules.ban_dest_port_list[i]);
			}
		}
		else{
			printf("DESTINATION PORT ALL ALLOWED\n");
			//rules.port_status = MAX + 1;
		}
	
}

void flush(int sockfd, socklen_t len){
	printf("FLUSH ALL THE RULES EXISTED\n");
	int i = 0;
	rules.tcp_status = 0;
	rules.udp_status = 0;
	// if(rules.icmp_status == 1)
	rules.icmp_status = 0;
	rules.dest_ip_status = MAX + 1;
    rules.source_ip_status = MAX + 1;
    rules.dest_port_status = MAX + 1;
	rules.source_port_status = MAX + 1;
	rules.ban_ip = 0;
	rules.ban_port = 0;
	for(i = 0;i <= MAX - 1;i++){
		rules.ban_source_ip_list[i] = 0;
        rules.ban_source_port_list[i] = 0;
        rules.ban_dest_ip_list[i] = 0;
        rules.ban_dest_port_list[i] = 0;
	}
	if(setsockopt(sockfd, IPPROTO_IP, FLUSH, &rules, len))
		printErr("setsockopt_Error!\n");
}

void block_ICMP_in(int sockfd, socklen_t len){
    rules.icmp_status = 1;
	if(setsockopt(sockfd, IPPROTO_IP, BANICMP, &rules, len))
		printErr("setsockopt_Error!\n");
}

void block_TCP_in(int sockfd, socklen_t len){
	rules.tcp_status = 1;
	if(setsockopt(sockfd, IPPROTO_IP, BANTCP, &rules, len))
		printErr("setsockopt_Error_TCP!\n");
}

void block_UDP_in(int sockfd, socklen_t len){
	rules.udp_status = 1;
	if(setsockopt(sockfd, IPPROTO_IP, BANUDP, &rules, len))
		printErr("setsockopt_Error_UDP!\n");
}



void block_IP_in(int sockfd, socklen_t len){
	if(rules.source_ip_status != 0){
		rules.ban_ip = inet_addr(sourceip);
		// int i;
		// for(i = 0;i <= MAX -1; i++){
		// 	if(rules.ban_ip == rules.ban_source_ip_list[i])
		// 		break;
		// 	else{
		// 		if(idx != 0){
		// 			rules.ban_source_ip_list[--idx] = rules.ban_ip;
		// 			break;
		// 		}
		// 	}
		// }
		// printf("----------------------------------------\n");
		// printf("\nip_status:%u\n",rules.source_ip_status);
		// printf("ban_ip:%u\n",rules.ban_ip);
		// printf("index:%d\n",idx);
		// printf("----------------------------------------\n");
		if(idx != 0)
			rules.ban_source_ip_list[--idx] = rules.ban_ip;
		if(setsockopt(sockfd, IPPROTO_IP, BANIP, &rules, len))
			printErr("setsockopt_IP_IN_ERROR!\n");
		rules.source_ip_status--;
	}else{
		rules.source_ip_status = 0;
		rules.ban_ip = 0;
		if(setsockopt(sockfd, IPPROTO_IP, BANIP, &rules, len))
			printErr("setsockopt_IP_IN_ERROR!\n");
	}
}

void block_IP_out(int sockfd, socklen_t len){
	if(rules.dest_ip_status != 0){
		rules.ban_ip = inet_addr(destip);
		// printf("----------------------------------------\n");
		// printf("\nip_status:%u\n",rules.ip_status);
		// printf("ban_ip:%u\n",rules.ban_ip);
		// printf("index:%d\n",idx);
		// printf("----------------------------------------\n");
		if(idx != 0)
			rules.ban_dest_ip_list[--idx] = rules.ban_ip;
		if(setsockopt(sockfd, IPPROTO_IP, BANIP, &rules, len))
			printErr("setsockopt_IP_OUT_ERROR!\n");
		rules.dest_ip_status--;
	}else{
		rules.dest_ip_status = 0;
		rules.ban_ip = 0;
		if(setsockopt(sockfd, IPPROTO_IP, BANIP, &rules, len))
			printErr("setsockopt_IP_OUT_ERROR!\n");
	}
}




void block_port_in(int sockfd, socklen_t len){
	if(rules.source_port_status != 0){
		rules.ban_port = atoi(sourceport);
		// printf("%d",rules.ban_port);
		if(idx != 0)
			rules.ban_source_port_list[--idx] = rules.ban_port;
		if(setsockopt(sockfd, IPPROTO_IP, BANPORT, &rules, len))
			printErr("setsockopt_port_in_ERROR!\n");
		rules.source_port_status -- ;
	 }else{ 
		rules.source_port_status = 0;
		rules.ban_port = 0;
		if(setsockopt(sockfd, IPPROTO_IP, BANPORT, &rules, len))
			printErr("setsockopt_port_in_ERROR!\n");
	}
}

void block_port_out(int sockfd, socklen_t len){
	if(rules.dest_port_status != 0){
		rules.ban_port = atoi(destport);
		if(idx != 0)
			rules.ban_dest_port_list[--idx] = rules.ban_port;
		if(setsockopt(sockfd, IPPROTO_IP, BANPORT, &rules, len))
			printErr("setsockopt_port_out_ERROR!\n");
		rules.dest_port_status -- ;
	 }else{ 
		rules.dest_port_status = 0;
		rules.ban_port = 0;
		if(setsockopt(sockfd, IPPROTO_IP, BANPORT, &rules, len))
			printErr("setsockopt_port_out_ERROR!\n");
	}
}






void rules_detail(int sockfd, socklen_t len){

	if(protocol != NULL && jump != NULL){
		if((strcmp(protocol,"icmp") == 0) && (strcmp(jump, "drop") == 0)){
			block_ICMP_in(sockfd, len);
		}else if((strcmp(protocol,"tcp") == 0) && (strcmp(jump, "drop") == 0)){
			block_TCP_in(sockfd, len);
		}else if((strcmp(protocol,"udp") == 0) && (strcmp(jump, "drop") == 0)){
			block_UDP_in(sockfd, len);
		}
	}else if(jump != NULL){
		if((strcmp(jump, "drop") == 0) && (sourceip != NULL))
			block_IP_in(sockfd, len);
		else if((destip != NULL) && (strcmp(jump, "drop") == 0))
			block_IP_out(sockfd, len);
		else if((sourceport != NULL) && (strcmp(jump, "drop") == 0))
			block_port_in(sockfd, len);
		else if((destport != NULL) && (strcmp(jump, "drop") == 0))
			block_port_out(sockfd, len);
	}else
		printf("Type -h for help!\n");



	// if(protocol == NULL || jump == NULL){
	// 	// printf("g!");
	// }else if((strcmp(protocol,"icmp") == 0 || strcmp(protocol,"ICMP") == 0) 
	// 			&& (strcmp(jump,"DROP") == 0 || strcmp(jump, "drop") == 0)){
	// 	block_ICMP_in(sockfd, len);
	// }else if((strcmp(protocol,"tcp") == 0 || strcmp(protocol, "TCP") == 0)
	// 			&& (strcmp(jump,"DROP") == 0 || strcmp(jump, "drop") == 0)){
	// 	block_TCP_in(sockfd, len);
	// }else if((strcmp(protocol,"udp") == 0 || strcmp(protocol, "UDP") == 0)
	// 			&& (strcmp(jump,"DROP") == 0 || strcmp(jump, "drop") == 0)){
	// 	block_UDP_in(sockfd, len);
	// }
	
	// if((sourceport != NULL) && (strcmp(jump,"DROP") == 0 || strcmp(jump, "drop") == 0))
	// 	block_port_in(sockfd, len);
	// if((destport != NULL)&& (strcmp(jump,"DROP") == 0 || strcmp(jump, "drop") == 0))
	// 	block_port_out(sockfd, len);
	// if((strcmp(protocol,"udp") == 0 || strcmp(protocol,"UDP") == 0)
	// 			&&(strcmp(jump,"DROP") == 0 || strcmp(jump, "drop") == 0)
	// 			&& destip != NULL 
	// 			&& destport != NULL){
	// 	block_UDP_out(sockfd, len);	
	// }

	// if((sourceip != NULL) && (strcmp(jump,"DROP") == 0 || strcmp(jump, "drop") == 0)&& destport == NULL)
	// 	block_IP_in(sockfd, len);
	
	// if((destip != NULL) && (strcmp(jump,"DROP") == 0 || strcmp(jump, "drop") == 0)&& destport == NULL)
	// 	block_IP_out(sockfd, len);

}
