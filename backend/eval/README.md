# Evaluation scripts (CS3002 metrics)

Run from `backend/` (locally or `docker compose run --rm backend <cmd>`).

## 1. Subdomain Recall Rate vs subfinder + Amass combined

```bash
# Baselines, both passive:
subfinder -d nmap.org -silent -all -o baselines/nmap.org.subfinder.txt
amass enum -passive -d nmap.org -o baselines/nmap.org.amass.txt

python -m eval.subdomain_recall --targets-file eval/targets.txt \
    --baseline-dir baselines/ --ours-dir ours/ --resolve-baseline
# or let it run the tools for missing files: add --run-subfinder --run-amass
```

The baseline is the union of both tools. Reports discovery recall (raw names),
live recall (only names that currently resolve), recall against each tool on its
own, Jaccard, per-target missed names, and our run time per domain.
Targets (`eval/targets.txt`): nmap.org (parent of scanme.nmap.org) and the
Acunetix test zone vulnweb.com, plus any bug-bounty/VDP domains you add.
Results: `eval/results/subdomain_recall.{json,csv,md}`.

## 2. CVE Mapping Precision (backport false positives)

```bash
# scan.json = Shodan InternetDB host records from Azaan's stage (or flat findings)
python -m eval.cve_precision template --scan scan.json --out eval/labels.csv
# ...label each row TP / FP / UNKNOWN; for FP set fp_reason (backport, version_misdetect, ...)
python -m eval.cve_precision score --labels eval/labels.csv
```

Ground truth comes from checking the package revision in the banner/CPE
against the distro's tracker (Ubuntu CVE tracker, Debian security tracker,
Red Hat CVE pages). The template pre-flags `backport_suspect` rows using
distro markers (e.g. `cpe:/o:canonical:ubuntu_linux`, `+deb10u5`, `.el7`).
Results: `eval/results/cve_precision.{json,md}`, including precision with and
without backport FPs, and precision split by distro-packaged vs upstream builds.
Per the proposal, run it on the public test hosts (scanme.nmap.org,
testphp.vulnweb.com, ...) and on a manually checked sample. Flagged rows are the
ones the dashboard should show as "potential" CVEs.

## 3. Ranking quality labels (CISA KEV)

The proposal scores ranking quality with KEV membership as the label. Get the
labels from the local cache (never use them as model inputs):

```python
from vulndb import VulnDB
labels = VulnDB().kev_labels(cve_ids)   # {cve_id: True/False}
```
