#!/usr/bin/env python3
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
from typing import Any


class Factory:
    """
    Mixin class that assists in the introduction of a factory method.
    """

    _registry: dict = dict()

    @classmethod
    def register(cls, tid: Any):
        """
        Assign a class to a Factory derivative under tid.

        All classes that are assigned should and should be assumed to
        conform to an identical interface.
        :return: A closure used as a decorator.
        """
        def type_id_dec(subclass):
            if tid in cls._registry:
                raise KeyError(
                    f'assigning {tid} to multiple subclasses of {cls}')
            cls._registry[tid] = subclass
            subclass.type_id = tid
            return subclass
        return type_id_dec

    @classmethod
    def lookup(cls, tid: Any) -> type:
        """
        Lookup in the registry and return a class.
        :param tid: The identifier of a subclass with a @register(tid)
        decorator.
        """
        try:
            subclass: type = cls._registry[tid]
        except KeyError as err:
            raise KeyError(
                f'{err.args[0]} is not an assigned identifier') from err
        return subclass
