./FuzzingBrain.sh https://github.com/google/skia -b 6a75afe9792764f6faa76ad50125781899ca05e8 -d 30d129c8800b5626c46fb83fa62db10b9b22b319


find . -type f -name "*.py" -exec chmod -v +x {} +
find . -type f -name "*.sh" -exec chmod -v +x {} +