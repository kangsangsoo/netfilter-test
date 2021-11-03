#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnet.h>

#define IPv4 4
#define IPv4_HDR_LENGTH 20
#define TCP 6

char* target;

void usage(void) {
	printf("syntax : netfilter-test <host>\n");
	printf("sample : netfilter-test test.gilgil.net\n");
}

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi;
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, &data);
	// ip패킷 시작
	if (ret >= 0)
		printf("payload_len=%d\n", ret);

	fputc('\n', stdout);

	return id;
}

static u_int32_t get_id (struct nfq_data *tb) {
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) id = ntohl(ph->packet_id);
	return id;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	unsigned char *data_;
	u_int32_t id = get_id(nfa);
	int ret = nfq_get_payload(nfa, &data_);

	struct libnet_ipv4_hdr ip_hdr;
	struct libnet_tcp_hdr tcp_hdr;

	// ip header 처리
	memcpy(&ip_hdr, data_, sizeof(struct libnet_ipv4_hdr));
	
	// version 확인
	if(ip_hdr.ip_v != IPv4) return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	// protocol 확인
	if(ip_hdr.ip_p != TCP) return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

	// ip_header_length 계산
	int ip_length = ip_hdr.ip_hl << 2;

	// tcp header 처리
	memcpy(&tcp_hdr, &data_[ip_length], sizeof(struct libnet_tcp_hdr));

	// 포트 확인
	if(ntohs(tcp_hdr.th_dport) != 80 && ntohs(tcp_hdr.th_sport) != 80) return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

	// tcp_header_length 계산
	int tcp_header_length = tcp_hdr.th_off << 2;

	// 페이로드 시작 위치 계산
	int tcp_segment_offset = ip_length + tcp_header_length;

	// 페이로드가 있는지 확인
	if(tcp_segment_offset == ret) return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);


	// HTTP 메서드인지 확인
	int i;
	const char* HTTP_METHOD = "HTTP";
	const char* CRLF = "\r\n";
	for(i = tcp_segment_offset; i < ret - strlen(HTTP_METHOD); i++) {
		if(strncmp(&data_[i], HTTP_METHOD, strlen(HTTP_METHOD)) == 0) {
			break;
		}
		// 첫번째 줄에 없으면 끝
		if(strncmp(&data_[i], CRLF, strlen(CRLF)) == 0) return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	}

	// "Host: test.gilgil.net\r\n" 확인
	const char* HOST = "Host: ";
	char* target_ = (char*)malloc(strlen(target)+9);
	memset(target_, 0, strlen(target)+9);
	// "Host: " + "주소" + "\r\n"
	strncpy(target_, HOST, strlen(HOST));
	strncpy(target_ + strlen(target_), target, strlen(target));
	strncpy(target_ + strlen(target_), CRLF, strlen(CRLF));

	for(; i < ret-strlen(target_); i++) {
		if(strncmp(&data_[i], target_, strlen(target_)) == 0) {
			printf("DROP\n");
			return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
		}
		// "Host: ~~"가 나왔는데 아니면 끝
		if(strncmp(&data_[i-1], HOST, strlen(HOST)) == 0) {
			return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
		}
	}
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	// 
	if(argc != 2) {
		usage();
		return 0;
	}
	target = argv[1];
	//

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			// printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
