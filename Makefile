all:
	# nothing

spellcheck: dict
	cargo spellcheck --fix

dict: target/tmp/dict.dic

target/tmp/dict.txt: .config/dict.txt
	mkdir -p $(dir $@)
	cat $< | sort | uniq > $@

target/tmp/dict.dic: target/tmp/dict.txt
	wc -l $< | awk '{print $$1}' > $@.tmp
	cat $< >> $@.tmp
	mv $@.tmp $@

.PHONY: dict spellcheck
