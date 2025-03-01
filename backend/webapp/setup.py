from setuptools import setup, find_packages

setup(
    name="reporter-tool",
    version="0.1",
    packages=find_packages(),
    install_requires=[
        'Flask==2.3.3',
        'Flask-SQLAlchemy==3.1.1',
        'Flask-Login==0.6.2',
        'Flask-WTF==1.1.1',
        'Flask-Migrate==4.0.4',
        'python-dotenv==1.0.0',
        'werkzeug==2.3.7',
        'email-validator==2.0.0',
        'cryptography==41.0.3',
        'boto3==1.28.36',
        'azure-storage-blob==12.17.0',
        'PyJWT==2.8.0',
        'requests==2.31.0'
    ]
) 