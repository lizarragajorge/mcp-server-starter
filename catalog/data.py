from typing import Annotated

from pydantic import BaseModel, ConfigDict, WithJsonSchema


class Character(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    homeworld: str
    affiliation: str


class CharacterList(BaseModel):
    # Copilot Studio documents limitations with referenced schemas; inline the item contract.
    characters: Annotated[
        list[Character],
        WithJsonSchema({"type": "array", "items": Character.model_json_schema()}),
    ]
    count: int


CATALOG = (
    Character(name="Luke Skywalker", homeworld="Tatooine", affiliation="Rebel Alliance"),
    Character(name="Leia Organa", homeworld="Alderaan", affiliation="Rebel Alliance"),
    Character(name="Darth Vader", homeworld="Tatooine", affiliation="Galactic Empire"),
    Character(name="Yoda", homeworld="Unknown", affiliation="Jedi Order"),
)
