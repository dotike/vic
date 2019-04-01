clean:
	rm -rf build

package: clean
	rm -f dist/process_dns_updates.zip
	mkdir -p build dist
	cp process_dns_updates.py build/
	pip install -r requirements.txt -t build/
	find build/ -name '*.pyc' -delete
	chmod -Rc ugo+rX build/
	cd build && zip ../dist/process_dns_updates.zip *

.PHONY: clean package
