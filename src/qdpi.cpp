#include "qdpi.h"
#include <stdlib.h>

#include "main.h"


static void *malloc_wrapper(unsigned long size)
{
	nfqFilter::current_ndpi_memory += size;
	if(nfqFilter::current_ndpi_memory > nfqFilter::max_ndpi_memory)
		nfqFilter::max_ndpi_memory = nfqFilter::current_ndpi_memory;
	return malloc(size);
}

static void free_wrapper(void *freeable)
{
	free(freeable);
}

void debug_printf(u_int32_t protocol, void *id_struct, ndpi_log_level_t log_level, const char *format, ...) {
    va_list va_ap;
    struct tm result;

    char buf[8192], out_buf[8192];
    char theDate[32];
    const char *extra_msg = "";
    time_t theTime = time(NULL);

    va_start (va_ap, format);

    /*
    if(log_level == NDPI_LOG_ERROR)
      extra_msg = "ERROR: ";
    else if(log_level == NDPI_LOG_TRACE)
      extra_msg = "TRACE: ";
    else.
      extra_msg = "DEBUG: ";
    */

    memset(buf, 0, sizeof(buf));
    strftime(theDate, 32, "%d/%b/%Y %H:%M:%S", localtime_r(&theTime, &result) );
    vsnprintf(buf, sizeof(buf)-1, format, va_ap);

    snprintf(out_buf, sizeof(out_buf), "%s %s%s", theDate, extra_msg, buf);
    printf("%s", out_buf);
    fflush(stdout);

    va_end(va_ap);
}

struct ndpi_detection_module_struct* init_ndpi()
{
	u_int32_t detection_tick_resolution = 1000;
	struct ndpi_detection_module_struct* my_ndpi_struct = ndpi_init_detection_module(detection_tick_resolution, malloc_wrapper, free_wrapper, debug_printf);

	if (my_ndpi_struct == NULL) {
		return NULL;
	}

	my_ndpi_struct->http_dont_dissect_response=1; // не ждем ответа http для разбора!!!

	NDPI_PROTOCOL_BITMASK all;
	// enable all protocols
	NDPI_BITMASK_SET_ALL(all);
	ndpi_set_protocol_detection_bitmask2(my_ndpi_struct, &all);

	return my_ndpi_struct;
}
