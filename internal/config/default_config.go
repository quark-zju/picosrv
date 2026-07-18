package config

type defaultEvaluator struct{}

func NewEvaluator() Evaluator {
	if evaluatorFactory != nil {
		return evaluatorFactory()
	}
	return defaultEvaluator{}
}

func (defaultEvaluator) Evaluate(EvaluationRequest) Decision {
	return Decision{Kind: DecisionDeny, Reason: "configuration_required"}
}

func (defaultEvaluator) IsKnownHost(string) bool {
	return false
}
