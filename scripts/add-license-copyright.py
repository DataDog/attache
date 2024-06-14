import requests

# This script adds the 'Copyright' column to the auto-generated LICENSE-3rdparty file
with open('LICENSE-3rdparty.csv', 'r') as file:
    thirdparty_licenses = file.read().rstrip('\n').split('\n')



# Input format is URL, link to license, License type
repos = {
    'golang.org/x/': 'The Go Authors',
    'github.com/hashicorp/': 'HashiCorp, Inc.',
    'github.com/DataDog/': 'Datadog, Inc.',
    'github.com/uber-go/': 'Uber Technologies, Inc.',
    'go.uber.org/': 'Uber Technologies, Inc.',
    'github.com/aws/': 'Amazon.com, Inc. or its affiliates',
    'github.com/cenkalti/backoff/': 'Cenk Altı',
    'github.com/cespare/xxhash/': 'Caleb Spare',
    'github.com/dustin/go-humanize': 'Dustin Sallings <dustin@spy.net>',
    'github.com/ebitengine/purego': 'Ebitengine',
    'github.com/go-jose/go-jose': 'Square Inc. and The Go Authors',
    'github.com/golang/protobuf': 'The Go Authors',
    'github.com/google/uuid': 'Google Inc.',
    'google.golang.org/': 'Google Inc.',
    'github.com/gorilla/mux': 'The Gorilla Authors',
    'github.com/mitchellh/': 'Mitchell Hashimoto',
    'github.com/outcaste-io/': 'Outcaste LLC',
    'github.com/philhofer/fwd': 'Phil Hofer',
    'github.com/pkg/errors': 'Dave Cheney <dave@cheney.net>',
    'github.com/ryanuber/go-glob': 'Ryan Uber',
    'github.com/secure-systems-lab/go-securesystemslib': 'NYU Secure Systems Lab',
    'github.com/tinylib/msgp': 'Philip Hofer and The Go Authors',
    'gopkg.in/DataDog/dd-trace-go': 'Datadog, Inc.'
}
for dependency in thirdparty_licenses:
    package, license_url, license_type = dependency.strip().split(',')
    author = None
    for repo_pattern, candidate_author in repos.items():
        if package.startswith(repo_pattern):
            author = candidate_author
            break

    if author is None:
        raise ValueError(f'No author found for {package}')
        
    print(f'{package},{license_url},{license_type},{author}')
    