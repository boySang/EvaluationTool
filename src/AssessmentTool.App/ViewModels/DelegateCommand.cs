using System;
using System.Windows.Input;

namespace AssessmentTool.App.ViewModels;

internal sealed class DelegateCommand : ICommand
{
    private readonly Action execute;
    private readonly Func<bool> canExecute;

    internal DelegateCommand(Action execute, Func<bool> canExecute)
    {
        this.execute = execute ?? throw new ArgumentNullException(nameof(execute));
        this.canExecute = canExecute ?? throw new ArgumentNullException(nameof(canExecute));
    }

    public event EventHandler? CanExecuteChanged;

    public bool CanExecute(object? parameter)
    {
        return canExecute();
    }

    public void Execute(object? parameter)
    {
        execute();
    }

    internal void RaiseCanExecuteChanged()
    {
        CanExecuteChanged?.Invoke(this, EventArgs.Empty);
    }
}

internal sealed class ParameterizedDelegateCommand<T> : ICommand
    where T : class
{
    private readonly Action<T> execute;
    private readonly Func<T, bool> canExecute;

    internal ParameterizedDelegateCommand(Action<T> execute, Func<T, bool> canExecute)
    {
        this.execute = execute ?? throw new ArgumentNullException(nameof(execute));
        this.canExecute = canExecute ?? throw new ArgumentNullException(nameof(canExecute));
    }

    public event EventHandler? CanExecuteChanged;

    public bool CanExecute(object? parameter)
    {
        return parameter is T value && canExecute(value);
    }

    public void Execute(object? parameter)
    {
        if (parameter is T value)
        {
            execute(value);
        }
    }

    internal void RaiseCanExecuteChanged()
    {
        CanExecuteChanged?.Invoke(this, EventArgs.Empty);
    }
}
