#include <stdint.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include "mgmt.h"

#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>

int mgmt_create(void)
{
	struct sockaddr_hci addr;
	int fd;

	fd = socket(PF_BLUETOOTH, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK,
                                                                BTPROTO_HCI);
	if (fd < 0)
		return -errno;

	memset(&addr, 0, sizeof(addr));
	addr.hci_family = AF_BLUETOOTH;
	addr.hci_dev = HCI_DEV_NONE;
	addr.hci_channel = HCI_CHANNEL_CONTROL;

	if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		int err = -errno;
		close(fd);
		return err;
	}

	return fd;
}

int main(void)
{
	int ble_sock = mgmt_create();

	if (ble_sock < 0)
	{
        perror("Cannot create socket\n");
        return 1;
	}
    
    struct mgmt_hdr hdr = {
        .opcode = htobs(0x1),
        .index = htobs(MGMT_INDEX_NONE),
        .len = 0
    };

    struct iovec iov;

    iov.iov_base = &hdr;
    iov.iov_len = sizeof(struct mgmt_hdr);

    if (writev(ble_sock, &iov, 1) < 0)
    {
        printf("Cannot send to BLE socket\n");
        return 1;
    }

    uint8_t buf[9];
    uint8_t version[3];
    struct iovec resp_iov[2] = {
        {.iov_base = buf, .iov_len = sizeof(buf)},
        {.iov_base = version, .iov_len = sizeof(version)}
    };

    if (readv(ble_sock, resp_iov, 2) < 0)
    {
        printf("Cannot read from socket\n");
        return 1;
    }

    uint16_t opcode = bt_get_le16(buf);
    uint16_t controller_idx = bt_get_le16(buf + 2);
    uint16_t param_len = bt_get_le16(buf + 4);
    uint16_t command_opcode = bt_get_le16(buf + 6);
    uint8_t status = *(buf + 8);
    printf("Opcode: %s, Index: %u, Paramlen: %u\n", mgmt_evstr(opcode), controller_idx, param_len);
    printf("Command: %s, status %s\n", mgmt_opstr(command_opcode), mgmt_errstr(status));

    if (opcode == 1)
    {
        uint8_t v = version[0];
        uint16_t rev = bt_get_le16(version + 1);
        printf("Version: %d, Revision %d\n", v, rev);
    }

    close(ble_sock);
    return 0;
}
