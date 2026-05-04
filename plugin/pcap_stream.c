/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Justin Thomas
 */

/* pcap_stream.c — plugin registration and one-time init. */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

#include <pcap_stream/pcap_stream.h>

pcap_stream_main_t pcap_stream_main;

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Live tcpdump-style packet capture (pcap_stream)",
};

static clib_error_t *
pcap_stream_init (vlib_main_t *vm)
{
  pcap_stream_main_t *psm = &pcap_stream_main;

  psm->vlib_main = vm;
  psm->vnet_main = vnet_get_main ();
  psm->next_session_id = 1;
  psm->control_socket_path = (char *) format (0, "%s%c",
					      PCAP_STREAM_CONTROL_SOCK_DEFAULT,
					      0);
  psm->control_listen_fd = -1;
  psm->initialized = 1;

  return pcap_stream_drain_init (vm);
}

VLIB_INIT_FUNCTION (pcap_stream_init);

/* --- vppctl debug commands --- */

static clib_error_t *
pcap_stream_show_command_fn (vlib_main_t *vm, unformat_input_t *input,
			     vlib_cli_command_t *cmd)
{
  pcap_stream_main_t *psm = &pcap_stream_main;
  u32 active = 0;

  for (u32 i = 0; i < PCAP_STREAM_MAX_SESSIONS; i++)
    {
      pcap_stream_session_t *s = &psm->sessions[i];
      if (!s->active)
	continue;
      active++;
      vlib_cli_output (
	  vm,
	  "session %u: iface=%U dir=0x%x snaplen=%u captured=%llu dropped=%llu",
	  s->session_id, format_vnet_sw_if_index_name, psm->vnet_main,
	  s->sw_if_index, s->direction, s->snaplen, s->captured, s->dropped);
      vlib_cli_output (vm, "  filter: %s", s->filter_expr);
    }
  if (!active)
    vlib_cli_output (vm, "no active sessions");
  vlib_cli_output (vm, "control socket: %s", psm->control_socket_path);
  return 0;
}

VLIB_CLI_COMMAND (pcap_stream_show_command, static) = {
  .path = "show pcap stream",
  .short_help = "show pcap stream",
  .function = pcap_stream_show_command_fn,
};
