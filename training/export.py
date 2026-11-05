#!/usr/bin/env python3
"""Export a trained model to the int8 ONNX files ModelNamer loads.

Usage: export.py <trained model dir> <output dir>
"""

import os
import shutil
import sys

from optimum.onnxruntime import ORTModelForSeq2SeqLM, ORTQuantizer
from optimum.onnxruntime.configuration import AutoQuantizationConfig

src, out = sys.argv[1], sys.argv[2]
tmp = out + "_fp32"
os.makedirs(out, exist_ok=True)
m = ORTModelForSeq2SeqLM.from_pretrained(
    src, export=True, use_cache=False, provider="CPUExecutionProvider"
)
m.save_pretrained(tmp)
print(os.listdir(tmp))
qc = AutoQuantizationConfig.avx2(is_static=False, per_channel=False)
for f in ("encoder_model.onnx", "decoder_model.onnx"):
    ORTQuantizer.from_pretrained(tmp, file_name=f).quantize(
        save_dir=out + "_q", quantization_config=qc
    )
    shutil.move(
        os.path.join(out + "_q", f.replace(".onnx", "_quantized.onnx")), os.path.join(out, f)
    )
shutil.copy(os.path.join(src, "tokenizer.json"), out)
shutil.rmtree(tmp)
shutil.rmtree(out + "_q", ignore_errors=True)
for f in os.listdir(out):
    print(f, os.path.getsize(os.path.join(out, f)) // 1024, "KB")
