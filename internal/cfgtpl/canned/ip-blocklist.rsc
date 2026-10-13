# Threat IP blocklist: the aggregated list from
# gitlab.com/multiduplikator-group/mikrotik_blocklist, kept in the address
# list prod_blocklist by the project's own update script, every 3 hours. Two
# RAW rules drop traffic from listed sources on the WAN, and to them from the
# LAN. The script is the project README's, unchanged but for the list file.
/interface list
ensure name=WAN
ensure name=LAN
/interface list member
ensure list=WAN interface={{wan_iface}}
ensure list=LAN interface={{lan_iface}}
/ip firewall raw
remove [ find comment="mdcfg:ip-blocklist" ]
add chain=prerouting action=drop in-interface-list=WAN src-address-list=prod_blocklist comment="mdcfg:ip-blocklist"
add chain=prerouting action=drop in-interface-list=LAN dst-address-list=prod_blocklist comment="mdcfg:ip-blocklist"
/system scheduler
remove [ find name="mdcfg-blocklist-update" ]
/system script
remove [ find name="mdcfg-blocklist-update" ]
add name=mdcfg-blocklist-update policy=ftp,read,write,sensitive,test comment="mdcfg:ip-blocklist" source=":local url \"https://multiduplikator-group.gitlab.io/mikrotik_blocklist/{{blocklist_file}}\"\
    \n:local file \"{{blocklist_file}}\"\
    \n:local listName \"prod_blocklist\"\
    \n:local block 32768\
    \n# Safety limits: abort if the list would grow or shrink by more than\
    \n# maxChange percent (raise it once when switching to another tier), and\
    \n# never add an entry wider than /minPrefix. Warn if the list is older than\
    \n# maxAge hours (the lists are regenerated hourly).\
    \n:local maxChange 30\
    \n:local minPrefix 10\
    \n:local maxAge 6\
    \n\
    \n# Only one run at a time: a second run (e.g. started by hand while the\
    \n# scheduled one is busy) stops before changing anything.\
    \n:local job [:jobname]\
    \n:if (([:len \$job] > 0) && ([/system script job print count-only as-value where script=\$job] > 1)) do={\
    \n    :log warning \"blocklist-DIFF: another run is still in progress, skipped\"\
    \n    :error \"blocklist update already running\"\
    \n}\
    \n\
    \n:log info \"blocklist-DIFF: === STARTED ===\"\
    \n:local startTime [:timestamp]\
    \n\
    \n# ----------------------------------------------------------------------------\
    \n# STEP 0: Download. Leave url empty to skip this and use \$file as it is.\
    \n# ----------------------------------------------------------------------------\
    \n:if (\$url != \"\") do={\
    \n    :do {\
    \n        # Verify the server certificate. Uses RouterOS's built-in root CAs\
    \n        # (7.19+, see Important Notes); on older versions import a CA bundle.\
    \n        /tool fetch url=\$url dst-path=\$file check-certificate=yes-without-crl\
    \n    } on-error={\
    \n        :log error \"blocklist-DIFF: download failed, list left unchanged\"\
    \n        :error \"blocklist download failed\"\
    \n    }\
    \n}\
    \n\
    \n# ----------------------------------------------------------------------------\
    \n# STEP 1: Load and verify the new list. Nothing is changed yet.\
    \n# The file is a sequence of 32 KB blocks, each one JSON object:\
    \n#   first octet -> second octet -> rest of the address -> 1\
    \n# deserialize builds each block's nested keyed array in one call.\
    \n# ----------------------------------------------------------------------------\
    \n:if ([:len [/file find name=\$file]] = 0) do={\
    \n    :log error \"blocklist-DIFF: \$file not found, aborting\"\
    \n    :error \"blocklist file missing\"\
    \n}\
    \n:local size [/file get \$file size]\
    \n:local bl [:toarray \"\"]\
    \n:local format 0\
    \n:local expected -1\
    \n:local generated \"\"\
    \n:do {\
    \n    :for off from=0 to=(\$size - 1) step=\$block do={\
    \n        :local r [/file read file=\$file offset=\$off chunk-size=\$block as-value]\
    \n        :local data (\$r->\"data\")\
    \n        :if ([:typeof \$data] = \"nothing\") do={ :set data \$r }\
    \n        :foreach o1,g in=[:deserialize from=json options=json.no-string-conversion \$data] do={\
    \n            :if (\$o1 = \"#\") do={\
    \n                :set format (\$g->\"format\")\
    \n                :set expected (\$g->\"entries\")\
    \n                :set generated (\$g->\"generated\")\
    \n            } else={\
    \n                :if ([:typeof (\$bl->\$o1)] = \"nothing\") do={\
    \n                    :set (\$bl->\$o1) \$g\
    \n                } else={\
    \n                    # first octet continues from the previous block: merge\
    \n                    :local b1 (\$bl->\$o1)\
    \n                    :foreach o2,rs in=\$g do={ :set (\$b1->\$o2) \$rs }\
    \n                    :set (\$bl->\$o1) \$b1\
    \n                }\
    \n            }\
    \n        }\
    \n    }\
    \n} on-error={\
    \n    :log error \"blocklist-DIFF: \$file is unreadable or not valid JSON (incomplete download?), aborting\"\
    \n    :error \"blocklist file unreadable\"\
    \n}\
    \n:local total 0\
    \n:foreach o1,g in=\$bl do={ :foreach o2,rs in=\$g do={ :set total (\$total + [:len \$rs]) } }\
    \n:if ((\$format != 1) || (\$total = 0) || (\$total != \$expected)) do={\
    \n    :log error \"blocklist-DIFF: \$file invalid (format \$format, \$total of \$expected entries), aborting\"\
    \n    :error \"blocklist file invalid\"\
    \n}\
    \n# The list is still applied when it is old: stale data beats no update.\
    \n:if ([:typeof \$generated] = \"num\") do={\
    \n    :local age ((([:tonsec [:timestamp]] / 1000000000) - \$generated) / 3600)\
    \n    :if (\$age >= \$maxAge) do={\
    \n        :log warning \"blocklist-DIFF: list was generated \$age hours ago (limit \$maxAge); is the GitLab schedule still running?\"\
    \n    }\
    \n} else={\
    \n    :log warning \"blocklist-DIFF: list has no generation time\"\
    \n}\
    \n:local current [:len [/ip firewall address-list find list=\$listName]]\
    \n:if (\$current > 0) do={\
    \n    :local change (\$total - \$current)\
    \n    :if (\$change < 0) do={ :set change (0 - \$change) }\
    \n    :if ((\$change * 100) > (\$current * \$maxChange)) do={\
    \n        :log error \"blocklist-DIFF: list would change from \$current to \$total entries (limit \$maxChange%), aborting\"\
    \n        :error \"blocklist change too large\"\
    \n    }\
    \n}\
    \n:log info \"blocklist-DIFF: Loaded \$total entries, list has \$current\"\
    \n\
    \n# ----------------------------------------------------------------------------\
    \n# STEP 2: Walk the current list. Entries still listed are kept and ticked\
    \n# off in \$bl; all others are removed. STEP 3: what is left in \$bl is new.\
    \n# ----------------------------------------------------------------------------\
    \n:local kept 0\
    \n:local removed 0\
    \n:local added 0\
    \n:local failed 0\
    \n:local skipped 0\
    \n\
    \n# Silence the info logging rule while the list changes (avoids thousands\
    \n# of add/remove messages); its previous state is restored afterwards.\
    \n:local logRule [:pick [/system logging find where topics~\"info\"] 0]\
    \n:local logWasOff true\
    \n:if ([:typeof \$logRule] = \"id\") do={\
    \n    :set logWasOff [/system logging get \$logRule disabled]\
    \n    /system logging disable \$logRule\
    \n}\
    \n\
    \n:do {\
    \n    /ip firewall address-list\
    \n    :foreach id in=[find list=\$listName] do={\
    \n        :local s [:tostr [get \$id address]]\
    \n        :local i1 [:find \$s \".\"]\
    \n        :local i2 [:find \$s \".\" \$i1]\
    \n        :local p1 [:pick \$s 0 \$i1]\
    \n        :local p2 [:pick \$s (\$i1 + 1) \$i2]\
    \n        :local rest [:pick \$s (\$i2 + 1) [:len \$s]]\
    \n        :if ([:typeof (((\$bl->\$p1)->\$p2)->\$rest)] != \"nothing\") do={\
    \n            # still listed: keep it, and tick it off in \$bl\
    \n            :set (((\$bl->\$p1)->\$p2)->\$rest)\
    \n            :set kept (\$kept + 1)\
    \n        } else={\
    \n            remove \$id\
    \n            :set removed (\$removed + 1)\
    \n        }\
    \n    }\
    \n\
    \n    :foreach o1,g in=\$bl do={\
    \n        :foreach o2,rs in=\$g do={\
    \n            :foreach rest,v in=\$rs do={\
    \n                :local plen 32\
    \n                :local slash [:find \$rest \"/\"]\
    \n                :if ([:typeof \$slash] != \"nil\") do={ :set plen [:tonum [:pick \$rest (\$slash + 1) [:len \$rest]]] }\
    \n                :if (([:typeof \$plen] = \"num\") && (\$plen < \$minPrefix)) do={\
    \n                    :set skipped (\$skipped + 1)\
    \n                } else={\
    \n                    # one bad entry must not stop the others\
    \n                    :do {\
    \n                        add list=\$listName address=(\$o1 . \".\" . \$o2 . \".\" . \$rest)\
    \n                        :set added (\$added + 1)\
    \n                    } on-error={ :set failed (\$failed + 1) }\
    \n                }\
    \n            }\
    \n        }\
    \n    }\
    \n} on-error={\
    \n    :if (([:typeof \$logRule] = \"id\") && !\$logWasOff) do={ /system logging enable \$logRule }\
    \n    :log error \"blocklist-DIFF: failed after removing \$removed and adding \$added entries\"\
    \n    :error \"blocklist update failed\"\
    \n}\
    \n\
    \n:if (([:typeof \$logRule] = \"id\") && !\$logWasOff) do={ /system logging enable \$logRule }\
    \n:set bl\
    \n\
    \n:local finalCount [:len [/ip firewall address-list find list=\$listName]]\
    \n:log info \"blocklist-DIFF: === COMPLETED ===\"\
    \n:log info \"blocklist-DIFF: Kept=\$kept, Removed=\$removed, Added=\$added, Total=\$finalCount\"\
    \n:if ((\$failed + \$skipped) > 0) do={\
    \n    :log warning \"blocklist-DIFF: \$failed entries could not be added, \$skipped skipped as wider than /\$minPrefix\"\
    \n}\
    \n:if (\$finalCount != (\$total - \$failed - \$skipped)) do={\
    \n    :log warning (\"blocklist-DIFF: list has \" . \$finalCount . \" entries, expected \" . (\$total - \$failed - \$skipped))\
    \n}\
    \n:log info (\"blocklist-DIFF: Duration=\" . ([:timestamp] - \$startTime))"
/system scheduler
add name=mdcfg-blocklist-update interval=3h start-time=00:10:00 on-event=mdcfg-blocklist-update policy=ftp,read,write,sensitive,test comment="mdcfg:ip-blocklist"
