#     Copyright mcendu 2019.
#
#     Licensed under the Apache License, Version 2.0 (the "License");
#     you may not use this file except in compliance with the License.
#     You may obtain a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#     Unless required by applicable law or agreed to in writing, software
#     distributed under the License is distributed on an "AS IS" BASIS,
#     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#     See the License for the specific language governing permissions and
#     limitations under the License.
"""A directory."""
from .File import File


class FileRef:
    def __init__(self, referent, mod=0o7):
        self.ref: File = referent
        self.mod = mod

    @property
    def __call__(self, *args, **kwargs):
        return self.ref

    @property
    def readable(self):
        return bool(self.mod & 0o4)

    @property
    def writable(self):
        return bool(self.mod & 0o2)

    @property
    def executable(self):
        return bool(self.mod & 0o1)


class Directory(File):
    pass
