#!/bin/bash
ROOT=app/build/outputs/apk/universal/release
zipalign -v -p 4 $ROOT/app-universal-release-unsigned.apk $ROOT/my-app-unsigned-aligned.apk
apksigner sign --ks my-release-key.jks --out $ROOT/my-app-release.apk $ROOT/my-app-unsigned-aligned.apk
