package whatsapp

import "core:testing"
import network_client "shared:surf"

Official_Version_Peer :: struct {
	calls: int,
	url:   string,
}
official_version_peer_get :: proc(
	data: rawptr,
	url: string,
	config: network_client.Config,
) -> (
	network_client.Response,
	network_client.HTTP_Error,
) {
	peer := cast(^Official_Version_Peer)data
	peer.calls += 1
	peer.url = url
	return {status = 200, body = transmute([]u8)string(`self.cfg={"client_revision":1234567890};`)}, {}
}

@(test)
official_version_discovery_does_not_use_third_party_feeds :: proc(t: ^testing.T) {
	peer: Official_Version_Peer
	result := web_version_discover({}, {data = &peer, get = official_version_peer_get})
	testing.expect_value(t, peer.calls, 1)
	testing.expect_value(t, peer.url, "https://web.whatsapp.com/sw.js")
	testing.expect_value(t, result.version, [3]u32{2, 3000, 1234567890})
	testing.expect(t, result.source != .Pinned)
}
