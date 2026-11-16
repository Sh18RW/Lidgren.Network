using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Net;
using System.Net.Sockets;

namespace Lidgren.Network;

/// <summary>
/// 
/// </summary>
/// <param name="inner"></param>
/// <param name="trustedProxies"></param>
public sealed class ProxyProtocolSocket(Socket inner, IEnumerable<IPAddress> trustedProxies) : IDisposable
{
	private readonly IPAddress[] _trustedProxies = trustedProxies.ToArray();

	/// <summary>
	/// 
	/// </summary>
	public IPEndPoint? LastRealSource { get; private set; }

	/// <summary>
	/// 
	/// </summary>
	/// <param name="buffer"></param>
	/// <param name="remoteEndPoint"></param>
	/// <returns></returns>
	public int ReceiveFrom(byte[] buffer, ref EndPoint remoteEndPoint)
	{
		var bytes = inner.ReceiveFrom(buffer, ref remoteEndPoint);
		LastRealSource = null;
		if (bytes <= 0 || !IsTrusted(remoteEndPoint))
		{
			return bytes;
		}

		var span = buffer.AsSpan(0, bytes);
		if (!ProxyProtocolParser.TryParse(span, out var realEndPoint, out var headerLen))
		{
			return bytes;
		}

		span[headerLen..].CopyTo(span);
		LastRealSource = realEndPoint;
		return bytes - headerLen;
	}

	private bool IsTrusted(EndPoint endPoint) =>
		endPoint is IPEndPoint ip && _trustedProxies.Contains(ip.Address);

	/// <summary>
	/// 
	/// </summary>
	/// <param name="localEndPoint"></param>
	public void Bind(EndPoint localEndPoint) => inner.Bind(localEndPoint);

	/// <summary>
	/// 
	/// </summary>
	/// <param name="buf"></param>
	/// <param name="endPoint"></param>
	/// <returns></returns>
	public int SendTo(byte[] buf, EndPoint endPoint) => inner.SendTo(buf, endPoint);

	/// <summary>
	/// 
	/// </summary>
	/// <param name="optionLevel"></param>
	/// <param name="optionName"></param>
	/// <param name="optionValue"></param>
	public void SetSocketOption(SocketOptionLevel optionLevel,
		SocketOptionName optionName,
		object optionValue)
		=> inner.SetSocketOption(optionLevel, optionName, optionValue);

	/// <summary>
	/// 
	/// </summary>
	/// <param name="micro"></param>
	/// <param name="mode"></param>
	/// <returns></returns>
	public bool Poll(int micro, SelectMode mode) => inner.Poll(micro, mode);

	/// <summary>
	/// 
	/// </summary>
	public int Available => inner.Available;

	/// <summary>
	/// 
	/// </summary>
	public bool Blocking
	{
		get => inner.Blocking;
		set => inner.Blocking = value;
	}

	/// <summary>
	/// 
	/// </summary>
	public void Close() => inner.Close();

	/// <summary>
	/// 
	/// </summary>
	public void Dispose() => inner.Dispose();
}