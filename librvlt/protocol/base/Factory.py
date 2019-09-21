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


class Factory:
    """
    Mixin class that introduces a factory method into a class (and its sub-
    classes).
    """

    _registry: dict = dict()

    @classmethod
    def type_id(cls, tid):
        """
        Inform the parent class of the existence of a subclass under
        the identifier of tid.
        """
        def type_id_dec(subclass):
            if tid in cls._registry:
                raise KeyError(
                    f'assigning {tid} to multiple subclasses of {cls}')
            cls._registry[tid] = subclass
            return subclass
        return type_id_dec

    @classmethod
    def create(cls, tid, *args, **kwargs):
        """
        Create an instance of this ABC.
        :param tid: The identifier of a subclass with a @type_id(tid)
        decorator.
        """
        try:
            subclass: type = cls._registry[tid]
        except KeyError as err:
            raise KeyError(
                f'{err.args[0]} is not an assigned identifier') from err
        return subclass(*args, **kwargs)
