rule Gafgyt_Botnet_generic : MALW 
{
	meta:
		description = "Gafgyt Trojan"
		author = "Joan Soriano / @joanbtl"
		date = "2017-05-01"
		version = "1.0"
		MD5 = "e3fac853203c3f1692af0101eaad87f1"
		SHA1 = "710781e62d49419a3a73624f4a914b2ad1684c6a"

	strings:
		$etcTZ = "/bin/busybox;echo -e 'gayfgt'"
		$s2 = "/proc/net/route"
		$s3 = "admin"
		$s4 = "microsoft"

	condition:
		$etcTZ or $s2 or $s3 or $s4
}
