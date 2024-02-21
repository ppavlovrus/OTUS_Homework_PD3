from setuptools import setup

setup(
    name='rest_web_service',
    version='0.1',
    description='A OOP REST service',
    author='Pavel Pavlov',
    author_email='ppavlovrus@gmail.com',
    packages=['src', 'tests'],
    install_requires=[],
    entry_points={
        #"console_scripts": [
       #     "nginx_log_analyzer = log_analyzer.py:main"
       # ]
    }
)
