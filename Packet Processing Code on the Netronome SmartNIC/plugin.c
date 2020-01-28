/*
 * Technion - Israel Institute of Technology
 *
 * Heavy-Hitter Detection on SmatNIC Project
 * Team: Yevhenii Liubchyk, Maria Shestakova
 * Instructors: Itzik Ashkenazi, Prof. Ori Rotenstreich
 */

#include <stdint.h>
#include <nfp/me.h>
#include <nfp/mem_atomic.h>
#include <pif_common.h>
#include "pif_plugin.h"
//============================================= UDP & TCP Protocols ==============================================
#define TCP_PROTO 0x06
#define UDP_PROTO 0x11
//================================= Hash-tables in the NetronomeSmartNIC memory ==================================
// Hash-table size
#define SKETCH_COLUMN_COUNT 128
#define SKETCH_COLUMN_COUNT_MASK (SKETCH_COLUMN_COUNT-1)
// Number of hash-tables
#define NUM_SKETCH 12
// Struct Heavy_Hitter stores flow identifier (for our project it is 5-tuple) and its counter
struct Heavy_Hitter {
	uint32_t srcAddr;
	uint32_t dstAddr;
	uint16_t srcPort;
	uint16_t dstPort;
	uint8_t protocol;
	uint32_t count;
};
// Save the result of HashPipe Algorith to variable sketch
__export __mem static struct Heavy_Hitter sketch[NUM_SKETCH][SKETCH_COLUMN_COUNT];
//================================== All hash-functions of HashPipe Algorithm ====================================
uint32_t hash_func(uint32_t function_num, struct Heavy_Hitter heavy_hitter) {
    if (function_num % 12 == 0) {
		return ((heavy_hitter.srcAddr ^ heavy_hitter.dstAddr) + heavy_hitter.protocol) & SKETCH_COLUMN_COUNT_MASK;
	}
	if (function_num % 12 == 1) {
		return ((heavy_hitter.srcAddr | heavy_hitter.dstAddr) + heavy_hitter.protocol) & SKETCH_COLUMN_COUNT_MASK;
	}
	if (function_num % 12 == 2) {
		return ((heavy_hitter.srcAddr & heavy_hitter.dstAddr) + heavy_hitter.protocol) & SKETCH_COLUMN_COUNT_MASK;
	}
    if (function_num % 12 == 3) {
		return ((heavy_hitter.srcPort ^ heavy_hitter.dstPort) + heavy_hitter.protocol) & SKETCH_COLUMN_COUNT_MASK;
	}
    if (function_num % 12 == 4) {
		return ((heavy_hitter.srcPort | heavy_hitter.dstPort) + heavy_hitter.protocol) & SKETCH_COLUMN_COUNT_MASK;
	}
    if (function_num % 12 == 5) {
		return ((heavy_hitter.srcPort & heavy_hitter.dstPort) + heavy_hitter.protocol) & SKETCH_COLUMN_COUNT_MASK;
	}
    if (function_num % 12 == 6) {
		return ((heavy_hitter.srcAddr ^ heavy_hitter.dstPort) + heavy_hitter.protocol) & SKETCH_COLUMN_COUNT_MASK;
	}
	if (function_num % 12 == 7) {
		return ((heavy_hitter.srcAddr | heavy_hitter.dstPort) + heavy_hitter.protocol) & SKETCH_COLUMN_COUNT_MASK;
	}
	if (function_num % 12 == 8) {
		return ((heavy_hitter.srcAddr & heavy_hitter.dstPort) + heavy_hitter.protocol) & SKETCH_COLUMN_COUNT_MASK;
	}
    if (function_num % 12 == 9) {
		return ((heavy_hitter.srcPort ^ heavy_hitter.dstAddr) + heavy_hitter.protocol) & SKETCH_COLUMN_COUNT_MASK;
	}
    if (function_num % 12 == 10) {
		return ((heavy_hitter.srcPort | heavy_hitter.dstAddr) + heavy_hitter.protocol) & SKETCH_COLUMN_COUNT_MASK;
	}
    if (function_num % 12 == 11) {
		return ((heavy_hitter.srcPort & heavy_hitter.dstAddr) + heavy_hitter.protocol) & SKETCH_COLUMN_COUNT_MASK;
	}
}
//============================================= Secondary functions ==============================================
// Compares 5-tuple of 2 given flows
uint32_t is_equal_keys(struct Heavy_Hitter heavy_hitter1, struct Heavy_Hitter heavy_hitter2) {
	if (heavy_hitter1.srcAddr == heavy_hitter2.srcAddr &&
		heavy_hitter1.dstAddr == heavy_hitter2.dstAddr &&
		heavy_hitter1.srcPort == heavy_hitter2.srcPort &&
		heavy_hitter1.dstPort == heavy_hitter2.dstPort &&
		heavy_hitter1.protocol == heavy_hitter2.protocol) {
		return 1;
	}
	return 0;
}

// Сhecks if a given flow exists 
uint32_t is_empty_slot(struct Heavy_Hitter heavy_hitter) {
	if (heavy_hitter.srcAddr == 0 &&
		heavy_hitter.dstAddr == 0 &&
		heavy_hitter.srcPort == 0 &&
		heavy_hitter.dstPort == 0 &&
		heavy_hitter.protocol == 0) {
		return 1;
	}
	return 0;	
}

// Returns the flow with the maximum counter of the 2 given flows
struct Heavy_Hitter max_count(struct Heavy_Hitter prev_heavy_hitter, struct Heavy_Hitter new_heavy_hitter) {
	if (prev_heavy_hitter.count < new_heavy_hitter.count) {
		return new_heavy_hitter;
	}
	return prev_heavy_hitter;
}

// Returns the flow with the minimum counter of the 2 given flows
struct Heavy_Hitter min_count(struct Heavy_Hitter prev_heavy_hitter, struct Heavy_Hitter new_heavy_hitter) {
	if (prev_heavy_hitter.count < new_heavy_hitter.count) {
		return prev_heavy_hitter;
	}
	return new_heavy_hitter;
}

//============================================= HashPipe Algorithm ===============================================
int pif_plugin_hashpipe_algorithm(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data)
{
	// Variables used to update sketch
	__xread struct Heavy_Hitter in_xfer_sketch;
	__xwrite struct Heavy_Hitter out_xfer_sketch;
	__gpr struct Heavy_Hitter input_heavy_hitter, curr_heavy_hitter;

	// Number of hash-table & number place in this hash-table (result of hash-funtion)
    uint32_t iterator, hv;
	
	// Download current packet from headers with the counter 1
	PIF_PLUGIN_ipv4_T *ipv4_header = pif_plugin_hdr_get_ipv4(headers);
	input_heavy_hitter.srcAddr = PIF_HEADER_GET_ipv4___srcAddr(ipv4_header);
	input_heavy_hitter.dstAddr = PIF_HEADER_GET_ipv4___dstAddr(ipv4_header);
	input_heavy_hitter.protocol = PIF_HEADER_GET_ipv4___protocol(ipv4_header);
	if (input_heavy_hitter.protocol == TCP_PROTO) {
		PIF_PLUGIN_tcp_T *tcp_header = pif_plugin_hdr_get_tcp(headers);
		input_heavy_hitter.srcPort = PIF_HEADER_GET_tcp___srcPort(tcp_header);
		input_heavy_hitter.dstPort = PIF_HEADER_GET_tcp___dstPort(tcp_header);
	}
	if (input_heavy_hitter.protocol == UDP_PROTO) {
		PIF_PLUGIN_udp_T *udp_header = pif_plugin_hdr_get_udp(headers);
		input_heavy_hitter.srcPort = PIF_HEADER_GET_udp___srcPort(udp_header);
		input_heavy_hitter.dstPort = PIF_HEADER_GET_udp___dstPort(udp_header);
	}
	
	input_heavy_hitter.count = 1;
	
	// First step of the algorithm
	hv = hash_func(0, input_heavy_hitter);
	
	mem_read_atomic(&in_xfer_sketch, &sketch[0][hv], sizeof(struct Heavy_Hitter));
	if (is_equal_keys(in_xfer_sketch, input_heavy_hitter)) {
		out_xfer_sketch = in_xfer_sketch;
		out_xfer_sketch.count = in_xfer_sketch.count + 1;
	} else {
		out_xfer_sketch = input_heavy_hitter;
	}
	mem_write_atomic(&out_xfer_sketch, &sketch[0][hv], sizeof(struct Heavy_Hitter));
	
	if (is_equal_keys(in_xfer_sketch, input_heavy_hitter) || is_empty_slot(in_xfer_sketch)) {
		return PIF_PLUGIN_RETURN_FORWARD;
	}
	curr_heavy_hitter = in_xfer_sketch;
	
	// The remaining steps of the algorithm
	for (iterator = 1; iterator < NUM_SKETCH; iterator++) {
		hv = hash_func(iterator, curr_heavy_hitter);
		
		mem_read_atomic(&in_xfer_sketch, &sketch[iterator][hv], sizeof(struct Heavy_Hitter));
		if (is_equal_keys(in_xfer_sketch, curr_heavy_hitter)) {
			out_xfer_sketch = in_xfer_sketch;
			out_xfer_sketch.count = in_xfer_sketch.count + curr_heavy_hitter.count;
		} else {
			out_xfer_sketch = max_count(in_xfer_sketch, curr_heavy_hitter);
		}
		mem_write_atomic(&out_xfer_sketch, &sketch[iterator][hv], sizeof(struct Heavy_Hitter));

		if (is_equal_keys(in_xfer_sketch, curr_heavy_hitter) || is_empty_slot(in_xfer_sketch)) {
			return PIF_PLUGIN_RETURN_FORWARD;
		}
		curr_heavy_hitter = min_count(in_xfer_sketch, curr_heavy_hitter);
	}
	
    return PIF_PLUGIN_RETURN_FORWARD;
};
