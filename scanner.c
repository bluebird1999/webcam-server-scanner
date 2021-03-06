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
#include "../../server/miio/miio_interface.h"
#include "../../server/miss/miss_interface.h"
#include "../../server/realtek/realtek_interface.h"
#include "../../server/device/device_interface.h"
#include "../../server/audio/audio_interface.h"
#include "../../server/recorder/recorder_interface.h"
//server header
#include "scanner.h"
#include "scanner_interface.h"
#include <zbar.h>

/*
 * static
 */
//variable
static pthread_mutex_t		s_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t		s_cond = PTHREAD_COND_INITIALIZER;
static server_info_t 		info;
static message_buffer_t		message;
static message_t 			msg_scan_t;
static zbar_image_scanner_t *scanner = NULL;
static zbar_image_t 		*image = NULL;
static int 					scanner_fun_exit = 0;
static int 					scanner_status = 0;
static int 					isp = -1;
static char 				zbar_buf[ZBAR_QRCODE_WIDTH * ZBAR_QRCODE_HIGH + 1] = {0};
static const char 			*key = "89JFSjo8HUbhou5776NJOMp9i90ghg7Y78G78t68899y79HY7g7y87y9ED45Ew30O0jkkl";
static int					motor_ready = 0;

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
static void *scanner_func(void *arg);
static int init_qrcode_isp(void);
static int init_scanner_config(void);
static int deinit_qrcode_isp(void);
static int deinit_scanner_config(void);
static int zbar_run(char **data);
static int zbar_process(struct rts_av_buffer *buffer, char **result);
static int iot_scan_code(message_t *data);
static void play_voice(int server_type, int type);
static void xor_crypt(const char *key, char *string, int n);
static unsigned char *base64_decode(unsigned char *code);
static int prase_data(char *src, char **dest);
static void *scanner_ctl_thread(void *arg);
static void my_free(char *data);
//specific

/*
 * %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
 * %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
 * %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
 */

/*
 * helper
 */
static void my_free(char *data)
{
   if(data)
	   free(data);
   data = NULL;
}

static int prase_data(char *src, char **dest)
{
	int ret = 0;
	char *p = NULL;
	char *bind_key = NULL;
	char *ssid = NULL;
	char *pssd = NULL;
	char *timezone = NULL;
	char *region = NULL;
	char *tmp = NULL;
	cJSON *pJsonRoot  = NULL;
	cJSON *pSubJson   = NULL;

	p = strsep(&src, "&");
	while(p != NULL)
	{
		if(strstr(p, "b="))
			bind_key = p+2;
		else if (strstr(p, "s="))
			ssid = p+2;
		else if (strstr(p, "p="))
			pssd = p+2;
		else if (strstr(p, "t="))
			timezone = p+2;
		else if (strstr(p, "r="))
			region = p+2;
		p = strsep(&src, "&");
	}

	if(ssid == NULL || pssd == NULL || bind_key == NULL || timezone == NULL)
	{
		log_qcy(DEBUG_SERIOUS, "scan error, please check qr code");
		return -1;
	}

	pJsonRoot = cJSON_CreateObject();
	if(NULL == pJsonRoot)
	{
		log_qcy(DEBUG_SERIOUS, "cJSON_CreateObject failed");
		return -1;
	}

	cJSON_AddNumberToObject(pJsonRoot, "id", 12345);
	cJSON_AddStringToObject(pJsonRoot, "method", "local.ble.config_router");
	pSubJson = cJSON_CreateObject();
	if(NULL == pSubJson)
	{
		log_qcy(DEBUG_SERIOUS, "cJSON_CreateObject failed");
		ret = -1;
		goto err;
	}

	if(ssid)
		ssid = base64_decode(ssid);
	if(pssd)
	{
		pssd = base64_decode(pssd);
		xor_crypt(key, pssd, strlen(pssd));
	}

	if(bind_key)
		cJSON_AddStringToObject(pSubJson, "bind_key", bind_key);
	if(ssid)
		cJSON_AddStringToObject(pSubJson, "ssid", ssid);
	if(pssd)
		cJSON_AddStringToObject(pSubJson, "passwd", pssd);
	if(timezone)
		cJSON_AddStringToObject(pSubJson, "tz", "Asia/Shanghai");
	if(region)
		cJSON_AddStringToObject(pSubJson, "country_domain", region);

	cJSON_AddItemToObject(pJsonRoot, "params", pSubJson);

	tmp = cJSON_Print(pJsonRoot);
	*dest = calloc(strlen(tmp) + 1, 1);
	if(*dest == NULL)
	{
		log_qcy(DEBUG_SERIOUS, "malloc failed");
		ret = -1;
		goto err;
	}

	memcpy(*dest, tmp, strlen(tmp));

err:
	my_free(ssid);
	my_free(pssd);

	cJSON_Delete(pJsonRoot);
	return ret;
}

static unsigned char *base64_decode(unsigned char *code)
{
    int table[]={0,0,0,0,0,0,0,0,0,0,0,0,
    		 0,0,0,0,0,0,0,0,0,0,0,0,
    		 0,0,0,0,0,0,0,0,0,0,0,0,
    		 0,0,0,0,0,0,0,62,0,0,0,
    		 63,52,53,54,55,56,57,58,
    		 59,60,61,0,0,0,0,0,0,0,0,
    		 1,2,3,4,5,6,7,8,9,10,11,12,
    		 13,14,15,16,17,18,19,20,21,
    		 22,23,24,25,0,0,0,0,0,0,26,
    		 27,28,29,30,31,32,33,34,35,
    		 36,37,38,39,40,41,42,43,44,
    		 45,46,47,48,49,50,51
    	       };
    long len;
    long str_len;
    unsigned char *res;
    int i,j;

    len=strlen(code);
    if(strstr(code,"=="))
        str_len=len/4*3-2;
    else if(strstr(code,"="))
        str_len=len/4*3-1;
    else
        str_len=len/4*3;

    res=calloc(1, sizeof(unsigned char)*str_len+1);
    res[str_len]='\0';

    for(i=0,j=0;i < len-2;j+=3,i+=4)
    {
        res[j]=((unsigned char)table[code[i]])<<2 | (((unsigned char)table[code[i+1]])>>4);
        res[j+1]=(((unsigned char)table[code[i+1]])<<4) | (((unsigned char)table[code[i+2]])>>2);
        res[j+2]=(((unsigned char)table[code[i+2]])<<6) | ((unsigned char)table[code[i+3]]);
    }

    return res;
}

static void xor_crypt(const char *key, char *string, int n)
{
    int i;
    int len = strlen(key);
    for (i = 0; i < n; i++)
    {
        string[i] = string[i] ^ key[i % len];
        if (string[i] == 0)
            string[i] = key[i % len];
    }
}

static void play_voice(int server_type, int type)
{
	message_t message;
	msg_init(&message);

	message.sender = message.receiver = server_type;
	message.message = MSG_AUDIO_SPEAKER_CTL_PLAY;
	message.arg_in.cat = type;

	server_audio_message(&message);
}

static void *scanner_ctl_thread(void *arg)
{
	message_t msg;
	int timer_num=0;
	log_qcy(DEBUG_INFO,"into scanner_ctl_thread");

	pthread_detach(pthread_self());
	while(!server_get_status(STATUS_TYPE_EXIT))
	{
		if(scanner_fun_exit)	break;
		timer_num++;
		if(timer_num == 1800)
		{
			play_voice(SERVER_SCANNER, SPEAKER_CTL_INTERNET_CONNECT_DEFEAT);
			int i = 0;
		    msg_init(&msg);
			msg.sender = msg.receiver = SERVER_SCANNER;
			msg.message = MSG_MANAGER_PROPERTY_SET;
			msg.arg_in.cat = MANAGER_PROPERTY_SLEEP;
			msg.arg = &i;
			msg.arg_size = sizeof(int);
			manager_common_send_message(SERVER_MANAGER, &msg);
			break;
		}
		if(!(timer_num%9))
		{
			if(motor_ready)
				play_voice(SERVER_SCANNER, SPEAKER_CTL_ZBAR_SCAN);
		}
		sleep(1);
	}

	log_qcy(DEBUG_INFO, "-----------thread exit: scanner_ctl_thread-----------");
	scanner_fun_exit = 0;
	pthread_exit(0);
}


static void *scanner_func(void *arg)
{
	int ret = 0;
	char *data = NULL;
	char *result = NULL;
	server_status_t st;
	message_t send_msg;

    signal(SIGINT, (__sighandler_t)server_thread_termination);
    signal(SIGTERM, (__sighandler_t)server_thread_termination);
	misc_set_thread_name("scanner_qr_thread");
    pthread_detach(pthread_self());
    msg_init(&send_msg);

	//message body
	ret = init_qrcode_isp();
	if(ret)
	{
		log_qcy(DEBUG_SERIOUS, "init_qrcode_isp failed");
		goto exit;
	}

	ret = init_scanner_config();
	if(ret)
	{
		log_qcy(DEBUG_SERIOUS, "init_scanner_config failed");
		goto exit;
	}

    while(!server_get_status(STATUS_TYPE_EXIT))
    {
		//exit logic
		st = server_get_status(STATUS_TYPE_STATUS);
    	if( st != STATUS_RUN ) {
			if ( st == STATUS_IDLE || st == STATUS_SETUP || st == STATUS_START)
				continue;
			else
				break;
		}

    	//get from device
    	if(!motor_ready)
    	{
    		send_msg.message = MSG_DEVICE_PROPERTY_GET;
    		send_msg.sender = send_msg.receiver = SERVER_SCANNER;
    		send_msg.arg_pass.cat = DEVICE_ACTION_MOTO_STATUS;
    		manager_common_send_message(SERVER_DEVICE, &send_msg);
    		/****************************/
    		usleep(MESSAGE_RESENT_SLEEP);
    		continue;
    	}

    	ret = zbar_run(&data);
		if(ret == 2)
		{
			log_qcy(DEBUG_INFO, "qr code is not right");
			my_free(data);
		}
		else if(ret == 1)
		{
			scanner_fun_exit = 1;
			break;
		}
		//free(data);
    }

	if(data != NULL)
	{
		ret = prase_data(data, &result);
		if(!ret)
		{
			log_qcy(DEBUG_INFO, "prase_data ------- result = %s", result);
			play_voice(SERVER_SCANNER, SPEAKER_CTL_ZBAR_SCAN_SUCCEED);

			send_iot_ack(&msg_scan_t, &send_msg, MSG_SCANNER_QR_CODE_BEGIN_ACK, msg_scan_t.receiver, ret,
								result, strlen(result) + 1);
		}
		else
			send_iot_ack(&msg_scan_t, &send_msg, MSG_SCANNER_QR_CODE_BEGIN_ACK, msg_scan_t.receiver, ret,
								NULL, 0);

		my_free(data);
		my_free(result);
	}

exit:
	scanner_status = 0;
	if(deinit_qrcode_isp())
		log_qcy(DEBUG_SERIOUS, "deinit_qrcode_isp failed");

	if(deinit_scanner_config())
		log_qcy(DEBUG_SERIOUS, "deinit_scanner_config failed");

	msg_free(&msg_scan_t);
	pthread_exit(0);
}

static int iot_scan_code(message_t *data)
{
	int ret = 0;
	static pthread_t scanner_mode_tid = 0;
	static pthread_t scanner_ctl_tid;
	if(scanner_status != 0)
	{
		log_qcy(DEBUG_SERIOUS, "scanner qr thread is busy");
		return -1;
	}

	msg_deep_copy(&msg_scan_t, data);

	if (ret |= pthread_create(&scanner_mode_tid, NULL, scanner_func, NULL)) {
		log_qcy(DEBUG_SERIOUS, "create daynight_mode_func thread failed, ret = %d\n", ret);
		ret = -1;
	} else {
		scanner_status = 1;
	}

	if (ret |= pthread_create(&scanner_ctl_tid,NULL,scanner_ctl_thread,NULL)) {
		log_qcy(DEBUG_SERIOUS, "create creat_scanner_ctl_thread thread failed, ret = %d\n", ret);
		ret = -1;
	}

	return ret;
}

static int zbar_process(struct rts_av_buffer *buffer, char **result)
{
    int ret = 1;

    printf("i am in zbar_process 111111\n");

    memset(zbar_buf, 0, sizeof(zbar_buf));

    printf("i am in zbar_process 22222 buffer->vm_addr = %p buffer->bytesused = %d, buffer->length = %d,\n",buffer->vm_addr, buffer->bytesused, buffer->length);
    memcpy(zbar_buf, buffer->vm_addr, ZBAR_QRCODE_WIDTH * ZBAR_QRCODE_HIGH);

    printf("i am in zbar_process 3333 image = %p, zbar_buf = %p\n",image ,zbar_buf);
    zbar_image_set_data(image, zbar_buf, ZBAR_QRCODE_WIDTH * ZBAR_QRCODE_HIGH, zbar_image_free_data);

    printf("i am in zbar_process 4444\n");
    /* scan the image for barcodes */
    int n = zbar_scan_image(scanner, image);
    printf("i am in zbar_process 5555\n");

    if(n != 0)
    	log_qcy(DEBUG_VERBOSE, "result1 n = %d\r\n", n);
    /* extract results */
    const zbar_symbol_t *symbol = zbar_image_first_symbol(image);
    printf("i am in zbar_process 6666\n");
    for(; symbol; symbol = zbar_symbol_next(symbol)) {
        /* do something useful with results */
//      zbar_symbol_type_t typ = zbar_symbol_get_type(symbol);
        const char *data = zbar_symbol_get_data(symbol);
        log_qcy(DEBUG_VERBOSE, "=========================================decoded QR CODE symbol \"%s\"\r\n",data);

        *result = calloc(strlen(data), 1);
        if(*result) {
        	memcpy(*result, data, strlen(data));
        	ret = 0;
        }
    }

    return ret;
}

static int zbar_run(char **data)
{
    int result = 1;
    int ret = 0;
    struct rts_av_buffer *buffer = NULL;

    if (rts_av_poll(isp)) {
        log_qcy(DEBUG_VERBOSE, "rts_av_poll isp failed");
        return 0;
    }
    if (rts_av_recv(isp, &buffer)) {
    	log_qcy(DEBUG_VERBOSE, "rts_av_recv isp buffer failed");
    	return 0;
    }
    if(buffer) {

        result = zbar_process(buffer, data);
        rts_av_put_buffer(buffer);
        buffer = NULL;
    }

    if(!result) {
        //count = 1000;
    	if(strstr(*data, "b=") && strstr(*data, "s=") && strstr(*data, "p=") && strstr(*data, "t="))
    		ret = 1;
    	else
    		ret = 2;
    }

    return ret;
}

static int deinit_scanner_config(void)
{
    if(scanner)
    {
    	zbar_image_scanner_destroy(scanner);
    	scanner = NULL;
    }
    if(image)
    {
    	zbar_image_destroy(image);
    	image = NULL;
    }

    return 0;
}

static int deinit_qrcode_isp(void)
{
    int ret;

    ret = rts_av_stop_recv(isp);
    if(ret)
    	log_info("rts_av_stop_recv isp ret = %d\r\n", ret);

    ret = rts_av_disable_chn(isp);
    if(ret)
    	log_info("rts_av_disable_chn isp ret = %d\r\n", ret);

    ret = rts_av_destroy_chn(isp);
    if(ret)
    	log_info("rts_av_destroy_chn isp ret = %d\r\n", ret);

    isp = -1;

    return ret;
}

static int init_scanner_config(void)
{
    scanner = zbar_image_scanner_create();
    if(!scanner)
    {
    	log_qcy(DEBUG_SERIOUS, "zbar_image_scanner_create failed");
    	return -1;
    }
    /* configure the reader */
    zbar_image_scanner_set_config(scanner, 0, ZBAR_CFG_ENABLE, 1);

    image = zbar_image_create();
	if(!image)
	{
		log_qcy(DEBUG_SERIOUS, "zbar_image_create failed");
		zbar_image_scanner_destroy(scanner);
		return -1;
	}

    zbar_image_set_format(image, *(int*)"Y800");
    zbar_image_set_size(image, ZBAR_QRCODE_WIDTH, ZBAR_QRCODE_HIGH);

    return 0;
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
            log_qcy(DEBUG_SERIOUS, "fail to create isp chn, ret = %d\n", isp);
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
                log_qcy(DEBUG_SERIOUS, "set isp profile fail, ret = %d\n", ret);

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
	msg.sender = msg.receiver = SERVER_SCANNER;
	msg.message = MSG_SCANNER_SIGINT;
	manager_message(&msg);
}

static int server_release(void)
{
	while(scanner_status || scanner_fun_exit)
		usleep(100 * 1000);

	msg_buffer_release(&message);
	memset(&info,0,sizeof(server_info_t));
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
		st = server_realtek_message(msg);
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
	msg->sender = msg->receiver = SERVER_SCANNER;
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
		log_qcy(DEBUG_SERIOUS, "add lock fail, ret = %d", ret);
		return ret;
	}
	if(type == STATUS_TYPE_STATUS)
		info.status = st;
	else if(type==STATUS_TYPE_EXIT)
		info.exit = st;
	ret = pthread_rwlock_unlock(&info.lock);
	if (ret)
		log_qcy(DEBUG_SERIOUS, "add unlock fail, ret = %d", ret);
	return ret;
}

static int server_get_status(int type)
{
	int st;
	int ret;
	ret = pthread_rwlock_wrlock(&info.lock);
	if(ret)	{
		log_qcy(DEBUG_SERIOUS, "add lock fail, ret = %d", ret);
		return ret;
	}
	if(type == STATUS_TYPE_STATUS)
		st = info.status;
	else if(type== STATUS_TYPE_EXIT)
		st = info.exit;
	ret = pthread_rwlock_unlock(&info.lock);
	if (ret)
		log_qcy(DEBUG_SERIOUS, "add unlock fail, ret = %d", ret);
	return st;
}

static int server_message_proc(void)
{
	int ret = 0, ret1 = 0;
	message_t msg;
	message_t send_msg;
	msg_init(&msg);
	msg_init(&send_msg);

	pthread_mutex_lock(&s_mutex);
	if( message.head == message.tail ) {
		if( info.status==STATUS_RUN ) {
			pthread_cond_wait(&s_cond,&s_mutex);
		}
	}
	pthread_mutex_unlock(&s_mutex);

	ret = pthread_rwlock_wrlock(&message.lock);
	if(ret)	{
		log_qcy(DEBUG_SERIOUS, "add message lock fail, ret = %d\n", ret);
		return ret;
	}

	ret = msg_buffer_pop(&message, &msg);
	ret1 = pthread_rwlock_unlock(&message.lock);
	if (ret1) {
		log_qcy(DEBUG_SERIOUS, "add message unlock fail, ret = %d\n", ret1);
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
			ret = iot_scan_code(&msg);
			break;
		case MSG_DEVICE_PROPERTY_GET_ACK:
			if(msg.arg_pass.cat == DEVICE_ACTION_MOTO_STATUS) {
				if(msg.arg_in.dog == 1)
					motor_ready = 1;
			}
			break;
		default:
			log_qcy(DEBUG_SERIOUS, "not processed message = %d", msg.message);
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
		log_qcy(DEBUG_SERIOUS, "error in message proc");

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
		log_qcy(DEBUG_SERIOUS, "scanner server create error! ret = %d",ret);
		 return ret;
	 }
	else {
		log_qcy(DEBUG_INFO, "scanner server create successful!");
		return 0;
	}
}

int server_scanner_message(message_t *msg)
{
	int ret=0,ret1;
	if( server_get_status(STATUS_TYPE_STATUS)!= STATUS_RUN ) {
		log_qcy(DEBUG_SERIOUS, "scanner server is not ready!");
		return -1;
	}
	ret = pthread_rwlock_wrlock(&message.lock);
	if(ret)	{
		log_qcy(DEBUG_SERIOUS, "add message lock fail, ret = %d\n", ret);
		return ret;
	}
	ret = msg_buffer_push(&message, msg);
	if( ret!=0 )
		log_qcy(DEBUG_SERIOUS, "message push in scanner error =%d", ret);
	else {
		pthread_mutex_lock(&s_mutex);
		pthread_cond_signal(&s_cond);
		pthread_mutex_unlock(&s_mutex);
	}

	ret1 = pthread_rwlock_unlock(&message.lock);
	if (ret1)
		log_qcy(DEBUG_SERIOUS, "add message unlock fail, ret = %d\n", ret1);
	return ret;
}
