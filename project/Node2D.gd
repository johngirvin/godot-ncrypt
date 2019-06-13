extends Node

func _ready():

	# run tests
	NCryptTest.new().run_all_tests()

	# run benchmarks
	NCryptBenchmark.new().run_all_tests()
	
	call_deferred('quit')
	return
