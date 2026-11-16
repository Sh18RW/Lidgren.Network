using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;

namespace Lidgren.Network;

public sealed class TrustedProxyList
{
	private readonly List<(IPAddress NetworkAddress, int PrefixLength)> _entries = [];

	public TrustedProxyList(string commaSeparatedCidrList)
	{
		if (string.IsNullOrWhiteSpace(commaSeparatedCidrList))
		{
			return;
		}

		foreach (var rawEntry in commaSeparatedCidrList.Split(
			         ',',
			         StringSplitOptions.RemoveEmptyEntries))
		{
			var trimmedEntry = rawEntry.Trim();
			if (TryParseCidr(trimmedEntry, out var networkAddress, out var prefixLength))
			{
				_entries.Add((networkAddress, prefixLength));
			}
		}
	}

	public bool IsTrusted(IPAddress addressToCheck)
	{
		if (_entries.Count == 0)
		{
			return false;
		}

		if (addressToCheck.IsIPv4MappedToIPv6)
		{
			addressToCheck = addressToCheck.MapToIPv4();
		}

		foreach (var (networkAddress, prefixLength) in _entries)
		{
			var candidateAddress = networkAddress.AddressFamily == addressToCheck.AddressFamily
				? addressToCheck
				: addressToCheck.MapToIPv6();

			if (Matches(candidateAddress, networkAddress, prefixLength))
			{
				return true;
			}
		}

		return false;
	}

	private static bool Matches(
		IPAddress address,
		IPAddress networkAddress,
		int prefixLength)
	{
		if (address.AddressFamily != networkAddress.AddressFamily)
		{
			return false;
		}

		var addressBytes = address.GetAddressBytes();
		var networkBytes = networkAddress.GetAddressBytes();

		var fullBytesCount = prefixLength / 8;
		var remainingBits = prefixLength % 8;

		for (var byteIndex = 0; byteIndex < fullBytesCount; byteIndex++)
		{
			if (addressBytes[byteIndex] != networkBytes[byteIndex])
			{
				return false;
			}
		}

		if (remainingBits <= 0)
		{
			return true;
		}

		var bitmask = 0xFF << (8 - remainingBits);
		return (addressBytes[fullBytesCount] & bitmask)
		       == (networkBytes[fullBytesCount] & bitmask);
	}

	private static bool TryParseCidr(
		string cidrString,
		out IPAddress networkAddress,
		out int prefixLength)
	{
		networkAddress = IPAddress.None;
		prefixLength = 0;

		var cidrParts = cidrString.Split('/');
		if (!IPAddress.TryParse(cidrParts[0], out var parsedAddress))
		{
			return false;
		}

		networkAddress = parsedAddress;

		if (cidrParts.Length == 1)
		{
			prefixLength = parsedAddress.AddressFamily == AddressFamily.InterNetwork
				? 32
				: 128;
			return true;
		}

		if (!int.TryParse(cidrParts[1], out prefixLength))
		{
			return false;
		}

		var maximumPrefixLength = parsedAddress.AddressFamily == AddressFamily.InterNetwork
			? 32
			: 128;

		return prefixLength is >= 0 and <= 128
		       && prefixLength <= maximumPrefixLength;
	}
}