from setuptools import setup

with open('README.md') as f:
    long_description = f.read()

setup(
    name='Flask-pyoidc',
    version='3.9.0',
    packages=['flask_pyoidc'],
    package_dir={'': 'src'},
    url='https://github.com/zamzterz/flask-pyoidc',
    license='Apache 2.0',
    author='Samuel Gulliksson',
    author_email='samuel.gulliksson@gmail.com',
    description='Flask extension for OpenID Connect authentication.',
    install_requires=[
        'oic>=1.2.1',
        'Flask',
        'requests',
        'importlib_resources'
    ],
    package_data={'flask_pyoidc': ['parse_fragment.html']},
    long_description=long_description,
    long_description_content_type='text/markdown',
)
