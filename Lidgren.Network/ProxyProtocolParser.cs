using System;
using System.Net;

namespace Lidgren.Network;

/// <summary>
/// 
/// </summary>
public static class ProxyProtocolParser
{
	private static ReadOnlySpan<byte> V2Signature => [0x0D,0x0A,0x0D,0x0A,0x00,0x0D,0x0A,0x51,0x55,0x49,0x54,0x0A];

	/// <summary>
	/// 
	/// </summary>
	/// <param name="data"></param>
	/// <param name="realSource"></param>
	/// <param name="headerLength"></param>
	/// <returns></returns>
	public static bool TryParse(ReadOnlySpan<byte> data, out IPEndPoint? realSource, out int headerLength)
	{
		realSource = null;
		headerLength = 0;

		if (data.Length >= 16 && data[..12].SequenceEqual(V2Signature))
		{
			return TryParseV2(data, out realSource, out headerLength);
		}

		if (data.Length >= 6 && data[..5].SequenceEqual("PROXY"u8))
		{
			return TryParseV1(data, out realSource, out headerLength);
		}

		return false;
	}

	private static bool TryParseV2(ReadOnlySpan<byte> data, out IPEndPoint? endPoint, out int length)
	{
		endPoint = null;
		length = 0;
		var versionCommand = data[12];
		if (versionCommand >> 4 != 0x2)
		{
			return false;
		}

		if ((versionCommand & 0x0F) != 0x1)
		{
			return false;
		}

		var famProto = data[13];
		var addressLength = (data[14] << 8) | data[15];
		length = 16 + addressLength;

		switch (famProto >> 4)
		{
			case 0x1: // AF_INET
				if (addressLength < 12)
				{
					return false;
				}
				var src4 = new IPAddress(data.Slice(16, 4));
				var port4 = (data[24] << 8) | data[25];
				endPoint = new IPEndPoint(src4, port4);
				return true;
			case 0x2: // AF_INET6
				if (addressLength < 36) return false;
				var src6 = new IPAddress(data.Slice(16, 16));
				var port6 = (data[32] << 8) | data[33];
				endPoint = new IPEndPoint(src6, port6);
				return true;
			default:
				return false;
		}
	}

	private static bool TryParseV1(ReadOnlySpan<byte> data, out IPEndPoint? endPoint, out int length)
	{
		endPoint = null;
		length = 0;
		var crlf = data.IndexOf("\r\n"u8);
		if (crlf is < 0 or > 107)
		{
			return false;
		}
		length = crlf + 2;

		// PROXY UDP4 <src> <dst> <sport> <dport>\r\n
		var line = System.Text.Encoding.ASCII.GetString(data[..crlf]);
		var parts = line.Split(' ');
		if (parts.Length < 6 || parts[0] != "PROXY")
		{
			return false;
		}
		if (parts[1] is not ("UDP4" or "UDP6" or "TCP4" or "TCP6"))
		{
			return false;
		}
		if (!IPAddress.TryParse(parts[2], out var src))
		{
			return false;
		}
		if (!int.TryParse(parts[4], out var sport))
		{
			return false;
		}
		endPoint = new IPEndPoint(src, sport);
		return true;
	}
}