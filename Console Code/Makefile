.PHONY: tcpdump tcpreplay result

tcpdump:
	sudo tcpdump -B 262144 -l -xx -n -v -i vf0_1 > RealHeavyHitterFlows

tcpreplay:
	sudo tcpreplay -L$(NUM) -i vf0_0 $(CAPTURE)
	sudo /opt/netronome/bin/nfp-rtsym i32._sketch.108 > HashPipeFlows
	sudo /opt/netronome/bin/nfp-rtsym i33._sketch.108 >> HashPipeFlows
	sudo /opt/netronome/bin/nfp-rtsym i34._sketch.108 >> HashPipeFlows
	sudo /opt/netronome/bin/nfp-rtsym i35._sketch.108 >> HashPipeFlows
	sudo /opt/netronome/bin/nfp-rtsym i36._sketch.108 >> HashPipeFlows

result:
	python getResult.py $(K)

