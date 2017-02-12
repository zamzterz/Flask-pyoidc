from setuptools import setup, find_packages

setup(
        name='Flask-pyoidc',
        version='1.1.0',
        packages=find_packages('src'),
        package_dir={'': 'src'},
        url='https://github.com/zamzterz/flask-pyoidc',
        license='Apache 2.0',
        author='Samuel Gulliksson',
        author_email='samuel.gulliksson@gmail.com',
        description='Flask extension for OpenID Connect authentication.',
        install_requires=[
            'oic==0.9.1.0',
            'Flask'
        ]
)
