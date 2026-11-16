using System;
using System.Net;
using System.Text;

namespace Lidgren.Network;

public static class ProxyProtocolParser
{
	private static readonly byte[] Version2Signature =
	[
		0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A,
		0x51, 0x55, 0x49, 0x54, 0x0A
	];

	private static readonly byte[] Version1Prefix = "PROXY "u8.ToArray();

	public static bool TryParse(
		ReadOnlySpan<byte> datagram,
		bool allowProxyProtocolVersion1,
		out IPEndPoint? realClientEndPoint,
		out int headerLength)
	{
		realClientEndPoint = null;
		headerLength = 0;

		if (StartsWith(datagram, Version2Signature))
		{
			return TryParseVersion2(datagram, out realClientEndPoint, out headerLength);
		}

		if (allowProxyProtocolVersion1 && StartsWith(datagram, Version1Prefix))
		{
			return TryParseVersion1(datagram, out realClientEndPoint, out headerLength);
		}

		return false;
	}

	private static bool StartsWith(ReadOnlySpan<byte> datagram, ReadOnlySpan<byte> prefix)
		=> datagram.Length >= prefix.Length
		   && datagram[..prefix.Length].SequenceEqual(prefix);

	private static bool TryParseVersion2(
		ReadOnlySpan<byte> datagram,
		out IPEndPoint? realClientEndPoint,
		out int headerLength)
	{
		realClientEndPoint = null;
		headerLength = 0;

		if (datagram.Length < 16)
		{
			return false;
		}

		var versionAndCommand = datagram[12];
		if ((versionAndCommand >> 4) != 0x2)
		{
			return false;
		}

		if ((versionAndCommand & 0x0F) != 0x1)
		{
			return false;
		}

		var addressFamilyAndProtocol = datagram[13];
		var addressLength = (datagram[14] << 8) | datagram[15];
		var totalLength = 16 + addressLength;
		if (datagram.Length < totalLength)
		{
			return false;
		}

		var addressFamily = addressFamilyAndProtocol >> 4;
		switch (addressFamily)
		{
			case 0x1: // AF_INET
			{
				if (addressLength < 12)
				{
					return false;
				}

				var sourceAddress = new IPAddress(datagram.Slice(16, 4));
				var sourcePort = (datagram[24] << 8) | datagram[25];

				realClientEndPoint = new IPEndPoint(sourceAddress, sourcePort);
				headerLength = totalLength;
				return true;
			}
			case 0x2: // AF_INET6
			{
				if (addressLength < 36)
				{
					return false;
				}

				var sourceAddress = new IPAddress(datagram.Slice(16, 16));
				var sourcePort = (datagram[32] << 8) | datagram[33];

				realClientEndPoint = new IPEndPoint(sourceAddress, sourcePort);
				headerLength = totalLength;
				return true;
			}
			default:
				return false;
		}
	}

	private static bool TryParseVersion1(
		ReadOnlySpan<byte> datagram,
		out IPEndPoint? realClientEndPoint,
		out int headerLength)
	{
		realClientEndPoint = null;
		headerLength = 0;

		var crlfIndex = -1;
		for (var index = 6; index + 1 < datagram.Length; index++)
		{
			if (datagram[index] != (byte)'\r' || datagram[index + 1] != (byte)'\n') continue;
			crlfIndex = index;
			break;
		}

		if (crlfIndex is < 0 or > 107)
		{
			return false;
		}

		var headerLine = Encoding.ASCII.GetString(datagram.Slice(0, crlfIndex).ToArray());
		var parts = headerLine.Split(' ');
		if (parts.Length < 6)
		{
			return false;
		}

		if (parts[0] != "PROXY")
		{
			return false;
		}

		var protocol = parts[1];
		if (protocol != "UDP4" && protocol != "UDP6" &&
		    protocol != "TCP4" && protocol != "TCP6")
		{
			return false;
		}

		if (!IPAddress.TryParse(parts[2], out var sourceAddress))
		{
			return false;
		}

		if (!int.TryParse(parts[4], out var sourcePort))
		{
			return false;
		}

		realClientEndPoint = new IPEndPoint(sourceAddress, sourcePort);
		headerLength = crlfIndex + 2;
		return true;
	}
}