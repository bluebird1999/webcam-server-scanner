/*
 * scanner.c
 *
 *  Created on: Aug 13, 2020
 *      Author: ning
 */

/*
 * header
 */
//system header
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <rtscamkit.h>
#include <rtsavapi.h>
#include <rtsvideo.h>
#include <malloc.h>
#include <string.h>
#include <unistd.h>
//#include <dmalloc.h>
//program header
#include "../../tools/tools_interface.h"
#include "../../manager/manager_interface.h"
//server header
#include "scanner.h"
#include "scanner_interface.h"
#include <zbar.h>

/*
 * static
 */
//variable
static int isp = -1;
static server_info_t 		info;
static message_buffer_t		message;
static char zbar_buf[ZBAR_QRCODE_WIDTH * ZBAR_QRCODE_HIGH] = {0};

//function
//common
static void *server_func(void);
static int server_message_proc(void);
static int server_none(void);
static int server_wait(void);
static int server_setup(void);
static int server_idle(void);
static int server_start(void);
static int server_run(void);
static int server_stop(void);
static int server_restart(void);
static int server_error(void);
static int server_release(void);
static int server_get_status(int type);
static int server_set_status(int type, int st);
static void server_thread_termination(void);
static int send_message(int receiver, message_t *msg);
static int send_iot_ack(message_t *org_msg, message_t *msg, int id, int receiver, int result, void *arg, int size);

static int init_qrcode_isp(void);
static int deinit_qrcode_isp(void);
static int zbar_run(char **data);
static char *zbar_process(struct rts_av_buffer *buffer, char **result);
static int iot_scan_code(char **data);
//specific

/*
 * %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
 * %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
 * %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
 */

/*
 * helper
 */
static int iot_scan_code(char **data)
{
	int ret = 0;
	ret = init_qrcode_isp();
	if(ret)
	{
		log_err("init_qrcode_isp failed");
		return -1;
	}

	while(!zbar_run(data));
	ret != deinit_qrcode_isp();
	{
		log_err("deinit_qrcode_isp failed");
		return -1;
	}

	return ret;
}

static char *zbar_process(struct rts_av_buffer *buffer, char **result)
{
    char *ret = NULL;
    zbar_image_scanner_t *scanner = NULL;

    scanner = zbar_image_scanner_create();
    /* configure the reader */
    zbar_image_scanner_set_config(scanner, 0, ZBAR_CFG_ENABLE, 1);

    zbar_image_t *image = zbar_image_create();
    zbar_image_set_format(image, *(int*)"Y800");
    zbar_image_set_size(image, ZBAR_QRCODE_WIDTH, ZBAR_QRCODE_HIGH);

    memset(zbar_buf, 0, sizeof(zbar_buf));
    memcpy(zbar_buf, buffer->vm_addr, ZBAR_QRCODE_WIDTH * ZBAR_QRCODE_HIGH);
    zbar_image_set_data(image, zbar_buf, ZBAR_QRCODE_WIDTH * ZBAR_QRCODE_HIGH, zbar_image_free_data);

    /* scan the image for barcodes */
    int n = zbar_scan_image(scanner, image);
    if(n != 0)
    	log_err("result1 n = %d\r\n", n);
    /* extract results */
    const zbar_symbol_t *symbol = zbar_image_first_symbol(image);
    for(; symbol; symbol = zbar_symbol_next(symbol)) {
        /* do something useful with results */
//      zbar_symbol_type_t typ = zbar_symbol_get_type(symbol);
        const char *data = zbar_symbol_get_data(symbol);
        log_err("=========================================decoded QR CODE symbol \"%s\"\r\n",data);

        *result = calloc(strlen(data), 1);
        if(*result) {
        	ret = memcpy(*result, data, strlen(data));
        }
    }

    zbar_image_destroy(image);
    zbar_image_scanner_destroy(scanner);

    return ret;
}

static int zbar_run(char **data)
{
    static int count = 0;
    char *result = NULL;
    struct rts_av_buffer *buffer = NULL;

    if (rts_av_poll(isp)) {
        //log_err("rts_av_poll isp failed");
        return 0;
    }
    if (rts_av_recv(isp, &buffer)) {
    	//log_err("rts_av_recv isp buffer failed");
    	return 0;
    }
    if(buffer) {
        if(count == 0) {
            result = zbar_process(buffer, data);
        }
        else {
            count--;
        }

        rts_av_put_buffer(buffer);
        buffer = NULL;
    }

    if(result != NULL) {
        //count = 1000;
        return 1;
    }

    return 0;
}

static int deinit_qrcode_isp(void)
{
    int ret;

    ret = rts_av_stop_recv(isp);
    log_info("rts_av_stop_recv isp ret = %d\r\n", ret);

    ret = rts_av_disable_chn(isp);
    log_info("rts_av_disable_chn isp ret = %d\r\n", ret);

    ret = rts_av_destroy_chn(isp);
    log_info("rts_av_destroy_chn isp ret = %d\r\n", ret);

    isp = -1;

    return ret;
}

static int init_qrcode_isp(void)
{
    int ret = 0;
    struct rts_isp_attr isp_attr;
    struct rts_av_profile profile;

    if(isp < 0) {
        isp_attr.isp_id = 1;
        isp_attr.isp_buf_num = 2;
        isp = rts_av_create_isp_chn(&isp_attr);
        if (isp < 0) {
            log_err("fail to create isp chn, ret = %d\n", isp);
            ret = -1;
        }
        log_info("isp chn : %d\n", isp);
        do {
            profile.fmt = RTS_V_FMT_YUV420SEMIPLANAR;
            profile.video.numerator = 1;
            profile.video.denominator = 15;
            profile.video.width = ZBAR_QRCODE_WIDTH;
            profile.video.height = ZBAR_QRCODE_HIGH;
            ret = rts_av_set_profile(isp, &profile);
            if (ret)
                log_err("set isp profile fail, ret = %d\n", ret);

            sleep(1);
        } while(ret);
    }

    ret = rts_av_enable_chn(isp);
    log_info("rts_av_enable_chn isp ret = %d\r\n", ret);

    ret = rts_av_start_recv(isp);
    log_info("rts_av_start_recv isp ret = %d\r\n", ret);

    return ret;
}

static void server_thread_termination(void)
{
	message_t msg;
	memset(&msg, 0, sizeof(message_t));
	msg.message = MSG_SCANNER_SIGINT;
	manager_message(&msg);
}

static int server_release(void)
{
	msg_buffer_release(&message);
	return 0;
}

static int send_message(int receiver, message_t *msg)
{
	int st;
	switch(receiver) {
	case SERVER_CONFIG:
//		st = server_config_message(msg);
		break;
	case SERVER_DEVICE:
		break;
	case SERVER_KERNEL:
		break;
	case SERVER_REALTEK:
		break;
	case SERVER_MIIO:
		st = server_miio_message(msg);
		break;
	case SERVER_MISS:
		st = server_miss_message(msg);
		break;
	case SERVER_MICLOUD:
		break;
	case SERVER_AUDIO:
		st = server_audio_message(msg);
		break;
	case SERVER_RECORDER:
		st = server_recorder_message(msg);
		break;
	case SERVER_PLAYER:
		break;
	case SERVER_MANAGER:
		st = manager_message(msg);
		break;
	}
	return st;
}

static int send_iot_ack(message_t *org_msg, message_t *msg, int id, int receiver, int result, void *arg, int size)
{
	int ret = 0;
    /********message body********/
	msg_init(msg);
	memcpy(&(msg->arg_pass), &(org_msg->arg_pass),sizeof(message_arg_t));
	msg->message = id | 0x1000;
	msg->sender = msg->receiver = SERVER_DEVICE;
	msg->result = result;
	msg->arg = arg;
	msg->arg_size = size;
	ret = send_message(receiver, msg);
	/***************************/
	return ret;
}

static int server_set_status(int type, int st)
{
	int ret=-1;
	ret = pthread_rwlock_wrlock(&info.lock);
	if(ret)	{
		log_err("add lock fail, ret = %d", ret);
		return ret;
	}
	if(type == STATUS_TYPE_STATUS)
		info.status = st;
	else if(type==STATUS_TYPE_EXIT)
		info.exit = st;
	ret = pthread_rwlock_unlock(&info.lock);
	if (ret)
		log_err("add unlock fail, ret = %d", ret);
	return ret;
}

static int server_get_status(int type)
{
	int st;
	int ret;
	ret = pthread_rwlock_wrlock(&info.lock);
	if(ret)	{
		log_err("add lock fail, ret = %d", ret);
		return ret;
	}
	if(type == STATUS_TYPE_STATUS)
		st = info.status;
	else if(type== STATUS_TYPE_EXIT)
		st = info.exit;
	ret = pthread_rwlock_unlock(&info.lock);
	if (ret)
		log_err("add unlock fail, ret = %d", ret);
	return st;
}

static int server_message_proc(void)
{
	int ret = 0, ret1 = 0;
	message_t msg;
	message_t send_msg;
	msg_init(&msg);
	msg_init(&send_msg);
	ret = pthread_rwlock_wrlock(&message.lock);
	if(ret)	{
		log_err("add message lock fail, ret = %d\n", ret);
		return ret;
	}
	ret = msg_buffer_pop(&message, &msg);
	ret1 = pthread_rwlock_unlock(&message.lock);
	if (ret1) {
		log_err("add message unlock fail, ret = %d\n", ret1);
	}
	if( ret == -1) {
		msg_free(&msg);
		return -1;
	}
	else if( ret == 1) {
		return 0;
	}
	switch(msg.message){
		case MSG_MANAGER_EXIT:
			server_set_status(STATUS_TYPE_EXIT,1);
			break;
		case MSG_MANAGER_TIMER_ACK:
			((HANDLER)msg.arg_in.handler)();
			break;
		case MSG_SCANNER_QR_CODE_BEGIN:
		{
			char *data = NULL;
			ret = iot_scan_code(&data);
			send_iot_ack(&msg, &send_msg, MSG_SCANNER_QR_CODE_BEGIN_ACK, msg.receiver, ret,
					data, strlen(data));
			if(data != NULL)
				free(data);
			break;
		}
		default:
			log_err("not processed message = %d", msg.message);
			break;
	}
	msg_free(&msg);
	return ret;
}

static int heart_beat_proc(void)
{
	int ret = 0;
	message_t msg;
	long long int tick = 0;
	tick = time_get_now_stamp();
	if( (tick - info.tick) > 10 ) {
		info.tick = tick;
	    /********message body********/
		msg_init(&msg);
		msg.message = MSG_MANAGER_HEARTBEAT;
		msg.sender = msg.receiver = SERVER_SCANNER;
		msg.arg_in.cat = info.status;
		msg.arg_in.dog = info.thread_start;
		msg.arg_in.duck = info.thread_exit;
		ret = manager_message(&msg);
		/***************************/
	}
	return ret;
}

/*
 * state machine
 */
static int server_none(void)
{
	server_set_status(STATUS_TYPE_STATUS, STATUS_WAIT);
	return 0;
}

static int server_wait(void)
{
	server_set_status(STATUS_TYPE_STATUS, STATUS_SETUP);
	return 0;
}

static int server_setup(void)
{
	int ret = 0;
	rts_set_log_mask(RTS_LOG_MASK_CONS);
	server_set_status(STATUS_TYPE_STATUS, STATUS_IDLE);
	return ret;
}

static int server_idle(void)
{
	int ret = 0;
	server_set_status(STATUS_TYPE_STATUS, STATUS_START);
	return ret;
}

static int server_start(void)
{
	int ret = 0;
	server_set_status(STATUS_TYPE_STATUS, STATUS_RUN);
	return ret;
}

static int server_run(void)
{
	int ret = 0;
	if( server_message_proc()!= 0)
		log_err("error in message proc");

	return ret;
}

static int server_stop(void)
{
	int ret = 0;
	return ret;
}

static int server_restart(void)
{
	int ret = 0;
	return ret;
}

static int server_error(void)
{
	int ret = 0;
	server_release();
	return ret;
}

static void *server_func(void)
{
    signal(SIGINT, (__sighandler_t)server_thread_termination);
    signal(SIGTERM, (__sighandler_t)server_thread_termination);
	misc_set_thread_name("server_scanner");
	pthread_detach(pthread_self());
	while( !info.exit ) {
	switch(info.status){
		case STATUS_NONE:
			server_none();
			break;
		case STATUS_WAIT:
			server_wait();
			break;
		case STATUS_SETUP:
			server_setup();
			break;
		case STATUS_IDLE:
			server_idle();
			break;
		case STATUS_START:
			server_start();
			break;
		case STATUS_RUN:
			server_run();
			break;
		case STATUS_STOP:
			server_stop();
			break;
		case STATUS_RESTART:
			server_restart();
			break;
		case STATUS_ERROR:
			server_error();
			break;
		}
//		usleep(100);//100ms
		heart_beat_proc();
	}
	server_release();
	log_info("-----------thread exit: server_scanner-----------");
	message_t msg;
    /********message body********/
	msg_init(&msg);
	msg.message = MSG_MANAGER_EXIT_ACK;
	msg.sender = SERVER_SCANNER;
	/****************************/
	manager_message(&msg);
	pthread_exit(0);
}

/*
 * external interface
 */
int server_scanner_start(void)
{
	int ret=-1;
	msg_buffer_init(&message, MSG_BUFFER_OVERFLOW_NO);
	pthread_rwlock_init(&info.lock, NULL);
	ret = pthread_create(&info.id, NULL, (void *)server_func, NULL);
	if(ret != 0) {
		log_err("scanner server create error! ret = %d",ret);
		 return ret;
	 }
	else {
		log_err("scanner server create successful!");
		return 0;
	}
}

int server_scanner_message(message_t *msg)
{
	int ret=0,ret1;
	if( server_get_status(STATUS_TYPE_STATUS)!= STATUS_RUN ) {
		log_err("scanner server is not ready!");
		return -1;
	}
	ret = pthread_rwlock_wrlock(&message.lock);
	if(ret)	{
		log_err("add message lock fail, ret = %d\n", ret);
		return ret;
	}
	ret = msg_buffer_push(&message, msg);
	if( ret!=0 )
		log_err("message push in scanner error =%d", ret);
	ret1 = pthread_rwlock_unlock(&message.lock);
	if (ret1)
		log_err("add message unlock fail, ret = %d\n", ret1);
	return ret;
}
