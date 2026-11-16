using System;
using System.Net;
using System.Net.Sockets;

namespace Lidgren.Network;

public sealed class ProxyProtocolSocket
{
	private readonly Socket _innerSocket;
	private readonly TrustedProxyList _trustedProxyList;
	private readonly bool _allowProxyProtocolVersion1;

	public IPEndPoint? LastRealSource { get; private set; }

	public ProxyProtocolSocket(
		Socket innerSocket,
		string commaSeparatedCidrList,
		bool allowProxyProtocolVersion1)
	{
		_innerSocket = innerSocket ?? throw new ArgumentNullException(nameof(innerSocket));
		_trustedProxyList = new TrustedProxyList(commaSeparatedCidrList);
		_allowProxyProtocolVersion1 = allowProxyProtocolVersion1;
	}

	internal int ReceiveFrom(
		byte[] buffer,
		int offset,
		int size,
		SocketFlags socketFlags,
		out NetSocketAddress senderAddress,
		ref EndPoint remoteEndPoint)
	{
		var bytesReceived = NetFastSocket.ReceiveFrom(
			_innerSocket, buffer, offset, size, socketFlags,
			out senderAddress, ref remoteEndPoint);

		LastRealSource = null;

		if (bytesReceived <= 0 || remoteEndPoint is not IPEndPoint remoteIpEndPoint ||
		    !_trustedProxyList.IsTrusted(remoteIpEndPoint.Address))
		{
			return bytesReceived;
		}

		var datagramSpan = buffer.AsSpan(offset, bytesReceived);
		if (!ProxyProtocolParser.TryParse(
			    datagramSpan,
			    _allowProxyProtocolVersion1,
			    out var realClientEndPoint,
			    out var headerLength))
		{
			return bytesReceived;
		}

		datagramSpan.Slice(headerLength).CopyTo(datagramSpan);
		LastRealSource = realClientEndPoint;
		return bytesReceived - headerLength;
	}
}