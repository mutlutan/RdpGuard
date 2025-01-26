using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace RdpGuard
{
	internal class Program
	{
		public static void Main(string[] args)
		{
			EventLog securityLog = new EventLog("Security");

			var failedLogins = securityLog.Entries.Cast<EventLogEntry>()
				.Where(entry => entry.InstanceId == 4625)
				.Where(entry => entry.TimeGenerated > DateTime.Now.Date)
				.LastOrDefault();

			int? index = failedLogins?.Index;

			Task.Factory.StartNew(() =>
			{
				while (true)
				{
					try
					{
						index = Dedect(index);
					}
					catch { }
					finally
					{
						Thread.Sleep(1000 * 10); //10 sn sonra 
					}
				}
			});
			Console.WriteLine("Login Failed Dedections Active : "+ DateTime.Now.ToString());
			Console.ReadLine();
		}

		private static int? Dedect(int? index)
		{
			int? rV = index;
			using (EventLog securityLog = new EventLog("Security"))
			{

				var failedLogins = securityLog.Entries.Cast<EventLogEntry>()
					.Where(entry => entry.InstanceId == 4625)
					.Where(entry => entry.TimeGenerated > DateTime.Now.Date);

				if (index != null)
				{
					failedLogins = failedLogins.Where(entry => entry.Index > index);
				}


				foreach (var entry in failedLogins)
				{
					rV = entry.Index;
					PrintEntry(entry);
				}
			}

			return rV;
		}

		private static void PrintEntry(EventLogEntry entry)
		{
			Console.WriteLine("");
			Console.WriteLine($"---------- Dedected index:{entry.Index} ----------");
			//Console.WriteLine("Entry Type : " + entry.EntryType + " InstanceId : " + entry.InstanceId);
			Console.WriteLine("Time Generated: " + entry.TimeGenerated);
			//Console.WriteLine("Source: " + entry.Source);
			Console.WriteLine("İş İstasyonu Adı: " + entry.ReplacementStrings[13]);
			Console.WriteLine("Hesap Adı: " + entry.ReplacementStrings[5]);
			Console.WriteLine("Kaynak Ağ Adresi: " + entry.ReplacementStrings[19]);
			Console.WriteLine("---------- Dedected End ----------");
		}

		private static void BlockIPAddress(string ipAddress)
		{
			// IP adresini Windows Firewall üzerinden engelle
			var process = new Process
			{
				StartInfo = new ProcessStartInfo
				{
					FileName = "netsh",
					Arguments = $"advfirewall firewall add rule name=\"Block {ipAddress}\" dir=in action=block remoteip={ipAddress}",
					RedirectStandardOutput = true,
					UseShellExecute = false,
					CreateNoWindow = true
				}
			};
			process.Start();
			string output = process.StandardOutput.ReadToEnd();
			process.WaitForExit();

			Console.WriteLine($"IP {ipAddress} başarıyla engellendi.");
		}
	}
}
