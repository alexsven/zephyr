/* btp_pbp.c - Bluetooth PBP Tester */

/*
 * Copyright (c) 2024 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "btp/btp.h"

#include <zephyr/bluetooth/audio/pbp.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/util.h>
#define LOG_MODULE_NAME bttester_pbp
LOG_MODULE_REGISTER(LOG_MODULE_NAME, CONFIG_BTTESTER_LOG_LEVEL);

#define PBP_EXT_ADV_METADATA_LEN_MAX 128

static uint8_t pbp_metadata_cached_len;
static uint8_t pbp_metadata_cached[PBP_EXT_ADV_METADATA_LEN_MAX];
static uint8_t pbp_name_cached_len;
static uint8_t pbp_features_cached;
static uint8_t pbp_broadcast_name_cached[BT_AUDIO_BROADCAST_NAME_LEN_MAX];

static bool scan_get_broadcast_name_len(struct bt_data *data, void *user_data)
{
	uint8_t *broadcast_name_len = user_data;

	switch (data->type) {
	case BT_DATA_BROADCAST_NAME:
		*broadcast_name_len = data->data_len;
		return false;
	default:
		return true;
	}
}

static bool scan_get_data(struct bt_data *data, void *user_data)
{
	uint8_t source_features;
	uint32_t broadcast_id;
	uint8_t metadata_len;
	uint8_t *metadata;
	struct btp_pbp_ev_public_broadcast_anouncement_found_rp *ev = user_data;

	switch (data->type) {
	case BT_DATA_BROADCAST_NAME:
		ev->broadcast_name_len = data->data_len;
		memcpy(ev->broadcast_name, data->data, data->data_len);
		return false;
	case BT_DATA_SVC_DATA16:
		broadcast_id = sys_get_le24(data->data + BT_UUID_SIZE_16);
		sys_put_le24(broadcast_id, ev->broadcast_id);
		metadata_len = bt_pbp_parse_announcement(data, &source_features, &metadata);
		ev->pba_features = source_features;
		return false;
	default:
		return true;
	}
}

static void pbp_scan_recv(const struct bt_le_scan_recv_info *info, struct net_buf_simple *ad)
{
	if ((info->adv_props & BT_GAP_ADV_PROP_CONNECTABLE) || info->interval == 0) {
		return;
	}

	uint8_t broadcast_name_len = 0;
	struct net_buf_simple ad_copy;

	net_buf_simple_clone(ad, &ad_copy);
	bt_data_parse(&ad_copy, scan_get_broadcast_name_len, &broadcast_name_len);

	struct btp_pbp_ev_public_broadcast_anouncement_found_rp *ev_ptr;

	tester_rsp_buffer_lock();
	tester_rsp_buffer_allocate(sizeof(*ev_ptr) + broadcast_name_len, (uint8_t **)&ev_ptr);

	bt_addr_le_copy(&ev_ptr->address, info->addr);
	ev_ptr->advertiser_sid = info->sid;
	ev_ptr->padv_interval = info->interval;
	bt_data_parse(ad, scan_get_data, ev_ptr);

	tester_event(BTP_SERVICE_ID_PBP, BTP_PBP_EV_PUBLIC_BROADCAST_ANOUNCEMENT_FOUND, ev_ptr,
		     sizeof(*ev_ptr) + broadcast_name_len);

	tester_rsp_buffer_free();
	tester_rsp_buffer_unlock();
}

static struct bt_le_scan_cb pbp_scan_cb = {
	.recv = pbp_scan_recv,
};

static uint8_t pbp_read_supported_commands(const void *cmd, uint16_t cmd_len, void *rsp,
					   uint16_t *rsp_len)
{
	struct btp_pbp_read_supported_commands_rp *rp = rsp;

	tester_set_bit(rp->data, BTP_PBP_READ_SUPPORTED_COMMANDS);
	tester_set_bit(rp->data, BTP_PBP_SET_PUBLIC_BROADCAST_ANNOUNCEMENT);
	tester_set_bit(rp->data, BTP_PBP_SET_BROADCAST_NAME);
	tester_set_bit(rp->data, BTP_PBP_BROADCAST_SCAN_START);
	tester_set_bit(rp->data, BTP_PBP_BROADCAST_SCAN_STOP);

	*rsp_len = sizeof(*rp) + 1;

	return BTP_STATUS_SUCCESS;
}

static int pbp_broadcast_source_adv_setup(void)
{
	struct bt_le_adv_param param =
		BT_LE_ADV_PARAM_INIT(0, BT_GAP_ADV_FAST_INT_MIN_2, BT_GAP_ADV_FAST_INT_MAX_2, NULL);
	uint32_t gap_settings =
		BIT(BTP_GAP_SETTINGS_DISCOVERABLE) | BIT(BTP_GAP_SETTINGS_EXTENDED_ADVERTISING);
	uint32_t broadcast_id = 0x123456;

	NET_BUF_SIMPLE_DEFINE(ad_buf, BT_UUID_SIZE_16 + BT_AUDIO_BROADCAST_ID_SIZE);
	NET_BUF_SIMPLE_DEFINE(pba_buf, BT_UUID_SIZE_16 + 3 + pbp_metadata_cached_len);

	int err;

	struct bt_data ext_ad[3];

	ext_ad[2].type = BT_DATA_BROADCAST_NAME;
	ext_ad[2].data_len = pbp_name_cached_len;
	ext_ad[2].data = pbp_broadcast_name_cached;
	net_buf_simple_add_le16(&ad_buf, BT_UUID_BROADCAST_AUDIO_VAL);
	net_buf_simple_add_le24(&ad_buf, broadcast_id);
	ext_ad[1].type = BT_DATA_SVC_DATA16;
	ext_ad[1].data_len = ad_buf.len;
	ext_ad[1].data = ad_buf.data;
	ext_ad[0].type = BT_DATA_SVC_DATA16;
	net_buf_simple_add_le16(&pba_buf, BT_UUID_PBA_VAL);
	net_buf_simple_add_u8(&pba_buf, pbp_features_cached);
	net_buf_simple_add_u8(&pba_buf, pbp_metadata_cached_len + 1);
	net_buf_simple_add_u8(&pba_buf, pbp_metadata_cached_len);
	net_buf_simple_add_mem(&pba_buf, pbp_metadata_cached, pbp_metadata_cached_len);
	ext_ad[0].data_len = pba_buf.len;
	ext_ad[0].data = pba_buf.data;

	err = tester_gap_create_adv_instance(&param, BTP_GAP_ADDR_TYPE_IDENTITY, ext_ad,
					     ARRAY_SIZE(ext_ad), NULL, 0, &gap_settings);
	if (err) {
		LOG_ERR("Could not set up extended advertisement: %d", err);
		return -EINVAL;
	}

	err = tester_gap_start_ext_adv();
	if (err) {
		LOG_ERR("Could not start extended advertisement: %d", err);
		return -EINVAL;
	}

	return 0;
}

static uint8_t pbp_set_public_broadcast_announcement(const void *cmd, uint16_t cmd_len, void *rsp,
						     uint16_t *rsp_len)
{
	const struct btp_pbp_set_public_broadcast_announcement_cmd *cp = cmd;
	int err = -EINVAL;

	if (cp->metadata_len <= PBP_EXT_ADV_METADATA_LEN_MAX) {
		pbp_metadata_cached_len = cp->metadata_len;
		pbp_features_cached = cp->features;

		memcpy(pbp_metadata_cached, cp->metadata, cp->metadata_len);
		err = pbp_broadcast_source_adv_setup();
	} else {
		LOG_ERR("Metadata too long: %d > %d", cp->metadata_len,
			PBP_EXT_ADV_METADATA_LEN_MAX);
	}

	return BTP_STATUS_VAL(err);
}

static uint8_t pbp_set_broadcast_name(const void *cmd, uint16_t cmd_len, void *rsp,
				      uint16_t *rsp_len)
{
	const struct btp_pbp_set_broadcast_name_cmd *cp = cmd;
	int err = -EINVAL;

	if (cp->name_len <= BT_AUDIO_BROADCAST_NAME_LEN_MAX) {
		pbp_name_cached_len = cp->name_len;
		memcpy(pbp_broadcast_name_cached, cp->name, cp->name_len);
		err = pbp_broadcast_source_adv_setup();
	} else {
		LOG_ERR("Broadcast name too long: %d > %d", cp->name_len,
			BT_AUDIO_BROADCAST_NAME_LEN_MAX);
	}

	return BTP_STATUS_VAL(err);
}

static uint8_t pbp_broadcast_scan_start(const void *cmd, uint16_t cmd_len, void *rsp,
					uint16_t *rsp_len)
{
	int err;

	LOG_DBG("Advertisement starting...");

	err = bt_le_scan_start(BT_LE_SCAN_ACTIVE, NULL);
	if (err != 0 && err != -EALREADY) {
		LOG_ERR("Unable to start scan for broadcast sources: %d", err);

		return BTP_STATUS_FAILED;
	}

	return BTP_STATUS_SUCCESS;
}

static uint8_t pbp_broadcast_scan_stop(const void *cmd, uint16_t cmd_len, void *rsp,
				       uint16_t *rsp_len)
{
	int err;

	LOG_DBG("Advertisement stopping...");

	err = bt_le_scan_stop();
	if (err != 0) {
		LOG_ERR("Failed to stop scan, %d", err);

		return BTP_STATUS_FAILED;
	}

	return BTP_STATUS_SUCCESS;
}

static const struct btp_handler pbp_handlers[] = {
	{.opcode = BTP_PBP_READ_SUPPORTED_COMMANDS,
	 .index = BTP_INDEX_NONE,
	 .expect_len = 0,
	 .func = pbp_read_supported_commands},
	{.opcode = BTP_PBP_SET_PUBLIC_BROADCAST_ANNOUNCEMENT,
	 .expect_len = BTP_HANDLER_LENGTH_VARIABLE,
	 .func = pbp_set_public_broadcast_announcement},
	{.opcode = BTP_PBP_SET_BROADCAST_NAME,
	 .expect_len = BTP_HANDLER_LENGTH_VARIABLE,
	 .func = pbp_set_broadcast_name},
	{.opcode = BTP_PBP_BROADCAST_SCAN_START,
	 .expect_len = sizeof(struct btp_pbp_broadcast_scan_start_cmd),
	 .func = pbp_broadcast_scan_start},
	{.opcode = BTP_PBP_BROADCAST_SCAN_STOP,
	 .expect_len = sizeof(struct btp_pbp_broadcast_scan_stop_cmd),
	 .func = pbp_broadcast_scan_stop}};

uint8_t tester_init_pbp(void)
{
	pbp_metadata_cached_len = 0;
	pbp_name_cached_len = 0;
	tester_register_command_handlers(BTP_SERVICE_ID_PBP, pbp_handlers,
					 ARRAY_SIZE(pbp_handlers));

	bt_le_scan_cb_register(&pbp_scan_cb);

	return BTP_STATUS_SUCCESS;
}

uint8_t tester_unregister_pbp(void)
{
	return BTP_STATUS_SUCCESS;
}