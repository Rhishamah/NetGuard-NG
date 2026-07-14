from pathlib import Path

from model.predict import load_models


class ModelRegistry:

    # Loads and stores machine learning models for the application.

    def __init__(self) -> None:
        self.random_forest = None

    def load(self) -> None:
        # Load the Random Forest model into memory.

        model_dir = Path("model") / "trained"

        self.random_forest = load_models(model_dir)

    def get_random_forest(self):
        """
        Return the loaded Random Forest model.
        """

        if self.random_forest is None:
            raise RuntimeError("Random Forest model has not been loaded.")

        return self.random_forest


registry = ModelRegistry()