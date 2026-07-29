from pathlib import Path
import os
import time

import torch
import transformers
from transformers import AutoModelForCausalLM, AutoTokenizer


MODEL_DIR = Path(
    "/home/openhitals/garak-lab/models/Qwen2.5-0.5B-Instruct"
).resolve()

REQUIRED_FILES = [
    "config.json",
    "generation_config.json",
    "model.safetensors",
    "tokenizer.json",
    "tokenizer_config.json",
]


def main() -> None:
    print("========== 本地模型推理测试 ==========")
    print("模型目录：", MODEL_DIR)
    print("PyTorch版本：", torch.__version__)
    print("Transformers版本：", transformers.__version__)
    print("CUDA是否可用：", torch.cuda.is_available())

    print("\n========== 文件检查 ==========")

    for filename in REQUIRED_FILES:
        path = MODEL_DIR / filename

        if not path.is_file():
            raise FileNotFoundError(f"缺少模型文件：{path}")

        print(f"[存在] {filename}")

    # 限制CPU线程数，防止虚拟机因线程过多反而变慢。
    cpu_threads = min(4, os.cpu_count() or 1)
    torch.set_num_threads(cpu_threads)

    print("\nCPU推理线程数：", cpu_threads)
    print("\n开始加载分词器和模型，请稍候……")

    load_start = time.perf_counter()

    tokenizer = AutoTokenizer.from_pretrained(
        str(MODEL_DIR),
        local_files_only=True,
        trust_remote_code=False,
    )

    # 使用float32可提高普通CPU环境的兼容性。
    model = AutoModelForCausalLM.from_pretrained(
        str(MODEL_DIR),
        local_files_only=True,
        trust_remote_code=False,
        torch_dtype=torch.float32,
        low_cpu_mem_usage=True,
    )

    model.eval()

    load_seconds = time.perf_counter() - load_start
    print(f"模型加载完成，耗时：{load_seconds:.2f} 秒")

    messages = [
        {
            "role": "system",
            "content": "你是一个简洁、可靠的中文助手。",
        },
        {
            "role": "user",
            "content": "请只回答：模型本地加载成功",
        },
    ]

    prompt = tokenizer.apply_chat_template(
        messages,
        tokenize=False,
        add_generation_prompt=True,
    )

    inputs = tokenizer(
        prompt,
        return_tensors="pt",
    )

    generation_start = time.perf_counter()

    with torch.inference_mode():
        output_ids = model.generate(
            **inputs,
            max_new_tokens=32,
            do_sample=False,
            pad_token_id=tokenizer.eos_token_id,
        )

    # 只保留模型新生成的token，不重复打印输入提示。
    generated_ids = output_ids[0][inputs["input_ids"].shape[1]:]

    response = tokenizer.decode(
        generated_ids,
        skip_special_tokens=True,
    ).strip()

    generation_seconds = time.perf_counter() - generation_start

    print("\n========== 推理结果 ==========")
    print("输入问题：请只回答：模型本地加载成功")
    print("模型回答：", response)
    print(f"推理耗时：{generation_seconds:.2f} 秒")

    if response:
        print("\n测试结论：本地模型能够正常加载并完成CPU推理")
    else:
        raise RuntimeError("模型没有生成有效回答")


if __name__ == "__main__":
    main()
