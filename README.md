<img src="https://github.com/TaylorBrennan/S3Sentinel/assets/44066496/4afa0c65-a188-460a-830b-16b0abbda7e6" width="350" />

> This tool is currently in active development and will receive regular updates, please ensure you're using the latest version!

# 🛡️ S3Sentinel - Bucket Security Scanner 🕵️‍♂️

S3Sentinel is your go-to tool for ensuring your AWS S3 buckets are fortified! 🚀 It comprehensively scans your S3 buckets, checking for public access settings and ensuring your data is secured. 🔐

## Features 🌟

- **Comprehensive Scans**: Deep dive into each bucket's ACL, policies, and public access settings. 📊
- **Object-Level Inspection**: Peeks into objects within buckets to check their accessibility. 🔍
- **User-Friendly**: Easy-to-use with clear, informative output. 🤖

## Getting Started 🚀

### Prerequisites

- Python 3.x 🐍
- AWS CLI configured with necessary permissions 🛠️
- Love for secure data! ❤️

### Installation 👨‍💻

1. Clone this repository:
   ```bash
   git clone https://github.com/TaylorBrennan/S3Sentinel.git
   ```
2. Install the required packages:
   ```bash
   pip install -r requirements.txt
   ```
### Usage

Simply run the script with your AWS Credentials:

```bash
python s3_sentinel.py <AWS_ACCESS_KEY_ID> <AWS_SECRET_ACCESS_KEY> [<AWS_SESSION_TOKEN>]
```
_👉 Don't forget to replace <AWS_ACCESS_KEY_ID>, <AWS_SECRET_ACCESS_KEY>, and <AWS_SESSION_TOKEN> with your actual AWS credentials._

## Example Output 📜

### Console

```
[1 / 1] Bucket: BUCKET_NAME
        - Bucket Status: Unknown
        - Public via ACL: False
        - Public via Policy: False
        - Access Block Set: False
        - Exceeded Object Threshold: False (1/400)
        - Public Objects: 1
                - PUBLIC_OBJECT_NAME.TXT
```

### JSON

```json
{
    "BUCKET_NAME": {
        "bucket_status": "Unknown",
        "total_objects": 1,
        "max_objects_scanned": 400,
        "total_public_objects": 1,
        "public_objects": [
            "PUBLIC_OBJECT_NAME.TXT"
        ],
        "public_via_acl": false,
        "public_via_policy": false,
        "access_block": false
    }
}
```

## Contributing

Contributions are what make the open-source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly** appreciated.

    1. Fork the Project
    2. Create your Feature Branch (git checkout -b feature/AmazingFeature)
    3. Commit your Changes (git commit -m 'Add some AmazingFeature')
    4. Push to the Branch (git push origin feature/AmazingFeature)
    5. Open a Pull Request

## License

Distributed under the MIT License. See `LICENSE` for more information.

## Support My Work ☕

If you find `S3Sentinel` helpful, consider supporting my work! Whether it's a cup of coffee or just a small token of appreciation, your support means a lot and helps me continue developing and improving tools like this.

[![Buy Me A Coffee](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/tbrennan)

Click the image above to buy me a coffee. Thank you for your support! 🙏

