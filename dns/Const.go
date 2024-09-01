package dns

var RCodeMap = map[uint8]string{
	0:  "NoError",  // No error condition
	1:  "FormErr",  // Format error
	2:  "ServFail", // Server failure
	3:  "NXDomain", // Non-Existent Domain
	4:  "NotImp",   // Not Implemented
	5:  "Refused",  // Query refused
	6:  "YXDomain", // Name Exists when it should not
	7:  "YXRRSet",  // RR Set Exists when it should not
	8:  "NXRRSet",  // RR Set that should exist does not
	9:  "NotAuth",  // Server Not Authoritative for zone
	10: "NotZone",  // Name not contained in zone
	// 11-15 are reserved for future use
}

var QRMap = map[bool]string{
	true:  "Response",
	false: "Request",
}

var QTypeMap = map[uint16]string{
	1:   "A",
	2:   "NS",
	3:   "MD", // Obsolete
	4:   "MF", // Obsolete
	5:   "CNAME",
	6:   "SOA",
	7:   "MB",   // Experimental
	8:   "MG",   // Experimental
	9:   "MR",   // Experimental
	10:  "NULL", // Experimental
	11:  "WKS",
	12:  "PTR",
	13:  "HINFO",
	14:  "MINFO",
	15:  "MX",
	16:  "TXT",
	65:  "HTTP", //No implemented, part of newer rfc
	252: "AXFR",
	253: "MAILB",
	254: "MAILA", // Obsolete
	255: "ANY",
}

var QClassMap = map[uint16]string{
	1:   "IN",  // Internet
	2:   "CS",  // CSNET (obsolete)
	3:   "CH",  // CHAOS
	4:   "HS",  // Hesiod
	255: "ANY", // Any class
}
