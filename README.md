# TA-centralops

## CentralOps Technology Add-On for Splunk

CentralOps provides 50 free normalised whois lookups every 24hrs via their web interface. Enterprise Security has a workflow action ("Domain Dossier") which pivots on domain fields to their service, however it would be advantageous if that information could enrich events at search-time. This app provides a `... | centralopswhois [output=<fields|json>] [limit=#] <domain_field_name>` streaming search command providing just that ability.

### Usage example

In searches designed to produce alerts (such as correlation searches), the centralopswhois command can be used to enrich events (if using ES, that enrichment is then included in the notables produced):

    | tstats `summariesonly` values(DNS.src) as src_ip from datamodel=Network_Resolution.DNS where NOT DNS.query="*.in-addr.arpa" by DNS.query
    | `drop_dm_object_name("DNS")`
    | eval domain=lower(query)
    | ...
    | lookup local=t centralopswhois_cache _key AS domain
    | centralopswhois output=json limit=2 domain
    | rename domain_whois as whois
    | eval now=now()
    | eval updated=if(isnull(updated),now,updated)
    | outputlookup append=t centralopswhois_cache
    | spath input=whois
    | rename *{} AS *
    | convert timeformat="%Y-%m-%dT%H:%M:%S%z" mktime(domain_creation_date)
    | where (now-domain_creation_date)<1209600  \\ domains less than 2 weeks old

Be sure to use the centralopswhois_cache lookup *before* the centralopswhois command, as it will not perform an external lookup if it has been retrieved from the cache (which is determined by the presence of a populated 'centralopswhois_domain' field). Equally, updating the centralopswhois_cache lookup after the centralopswhois command is important so subsequent searches can use the cached information.

### Features

- Caching of looked up whois information both within a given search (i.e. if the same domain appears in multiple events, the lookup only occurs once) and outside search (using a KV Store collection) to cache historical lookups
- DoS protection - by default only the first 5 uncached domains will be looked up in a search
- Proxy support (configurable via app setup page)
- Whois dashboard and pre-built panel
- Workflow actions providing pivot from domain fields to whois dashboard
- Automatically summary indexes new whois records (disabled by default)

### Disclaimer

The author in no way endorses the provider's service, has no affiliation whatsoever with the provider, and makes no guarantees about the quality or accuracy of the information provided.
