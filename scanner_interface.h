/*
 * scanner_interface.h
 *
 *
 *      Author: lijunxin
 */

#ifndef SERVER_SCANNER_INTERFACE_H_
#define SERVER_SCANNER_INTERFACE_H_

/*
 * header
 */
#include "../../manager/manager_interface.h"

/*
 * define
 */
#define		SERVER_SCANNER_VERSION_STRING			"alpha-1.1"

#define		MSG_SCANNER_BASE						(SERVER_SCANNER<<16)
#define		MSG_SCANNER_SIGINT						MSG_SCANNER_BASE | 0x0000
#define		MSG_SCANNER_SIGINT_ACK					MSG_SCANNER_BASE | 0x1000


#define		MSG_SCANNER_QR_CODE_BEGIN				MSG_SCANNER_BASE | 0x0001
#define		MSG_SCANNER_QR_CODE_BEGIN_ACK			MSG_SCANNER_BASE | 0x1001

/*
 * structure
 */

/*
 * function
 */
int server_scanner_start(void);
int server_scanner_message(message_t *msg);

#endif /* SERVER_SCANNER_INTERFACE_H_ */
